rule TTP_XOR_QUAD_CurrentVersionRun_2ffe {
  strings:
    $key_2ffe = { 7c 91 [2] 58 9f [2] 73 b3 [2] 5d 91 [2] 49 8a [2] 46 90 [2] 58 8d [2] 5a 8c [2] 41 8a [2] 5d 8d [2] 41 a2 }

  condition:
    any of them
}
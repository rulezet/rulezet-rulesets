rule TTP_XOR_QUAD_CurrentVersionRun_0ffe {
  strings:
    $key_0ffe = { 5c 91 [2] 78 9f [2] 53 b3 [2] 7d 91 [2] 69 8a [2] 66 90 [2] 78 8d [2] 7a 8c [2] 61 8a [2] 7d 8d [2] 61 a2 }

  condition:
    any of them
}
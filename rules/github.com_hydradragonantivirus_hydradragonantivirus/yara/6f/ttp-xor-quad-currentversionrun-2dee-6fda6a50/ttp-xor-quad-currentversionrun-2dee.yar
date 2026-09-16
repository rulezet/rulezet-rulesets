rule TTP_XOR_QUAD_CurrentVersionRun_2dee {
  strings:
    $key_2dee = { 7e 81 [2] 5a 8f [2] 71 a3 [2] 5f 81 [2] 4b 9a [2] 44 80 [2] 5a 9d [2] 58 9c [2] 43 9a [2] 5f 9d [2] 43 b2 }

  condition:
    any of them
}
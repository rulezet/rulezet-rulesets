rule TTP_XOR_QUAD_CurrentVersionRun_2afe {
  strings:
    $key_2afe = { 79 91 [2] 5d 9f [2] 76 b3 [2] 58 91 [2] 4c 8a [2] 43 90 [2] 5d 8d [2] 5f 8c [2] 44 8a [2] 58 8d [2] 44 a2 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_2a0e {
  strings:
    $key_2a0e = { 79 61 [2] 5d 6f [2] 76 43 [2] 58 61 [2] 4c 7a [2] 43 60 [2] 5d 7d [2] 5f 7c [2] 44 7a [2] 58 7d [2] 44 52 }

  condition:
    any of them
}
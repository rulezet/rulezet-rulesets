rule TTP_XOR_QUAD_CurrentVersionRun_2a3e {
  strings:
    $key_2a3e = { 79 51 [2] 5d 5f [2] 76 73 [2] 58 51 [2] 4c 4a [2] 43 50 [2] 5d 4d [2] 5f 4c [2] 44 4a [2] 58 4d [2] 44 62 }

  condition:
    any of them
}
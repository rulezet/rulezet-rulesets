rule TTP_XOR_QUAD_CurrentVersionRun_e83e {
  strings:
    $key_e83e = { bb 51 [2] 9f 5f [2] b4 73 [2] 9a 51 [2] 8e 4a [2] 81 50 [2] 9f 4d [2] 9d 4c [2] 86 4a [2] 9a 4d [2] 86 62 }

  condition:
    any of them
}
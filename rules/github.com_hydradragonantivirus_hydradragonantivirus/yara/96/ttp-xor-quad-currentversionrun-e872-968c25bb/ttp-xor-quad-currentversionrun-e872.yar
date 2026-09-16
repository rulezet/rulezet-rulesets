rule TTP_XOR_QUAD_CurrentVersionRun_e872 {
  strings:
    $key_e872 = { bb 1d [2] 9f 13 [2] b4 3f [2] 9a 1d [2] 8e 06 [2] 81 1c [2] 9f 01 [2] 9d 00 [2] 86 06 [2] 9a 01 [2] 86 2e }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_e812 {
  strings:
    $key_e812 = { bb 7d [2] 9f 73 [2] b4 5f [2] 9a 7d [2] 8e 66 [2] 81 7c [2] 9f 61 [2] 9d 60 [2] 86 66 [2] 9a 61 [2] 86 4e }

  condition:
    any of them
}
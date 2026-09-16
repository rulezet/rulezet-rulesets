rule TTP_XOR_QUAD_CurrentVersionRun_e807 {
  strings:
    $key_e807 = { bb 68 [2] 9f 66 [2] b4 4a [2] 9a 68 [2] 8e 73 [2] 81 69 [2] 9f 74 [2] 9d 75 [2] 86 73 [2] 9a 74 [2] 86 5b }

  condition:
    any of them
}
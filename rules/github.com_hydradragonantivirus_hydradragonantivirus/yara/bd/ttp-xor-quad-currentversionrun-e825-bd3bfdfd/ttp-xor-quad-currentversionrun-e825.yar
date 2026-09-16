rule TTP_XOR_QUAD_CurrentVersionRun_e825 {
  strings:
    $key_e825 = { bb 4a [2] 9f 44 [2] b4 68 [2] 9a 4a [2] 8e 51 [2] 81 4b [2] 9f 56 [2] 9d 57 [2] 86 51 [2] 9a 56 [2] 86 79 }

  condition:
    any of them
}
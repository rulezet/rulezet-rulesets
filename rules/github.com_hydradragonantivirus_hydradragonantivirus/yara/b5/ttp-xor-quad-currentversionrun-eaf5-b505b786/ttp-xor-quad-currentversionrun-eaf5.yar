rule TTP_XOR_QUAD_CurrentVersionRun_eaf5 {
  strings:
    $key_eaf5 = { b9 9a [2] 9d 94 [2] b6 b8 [2] 98 9a [2] 8c 81 [2] 83 9b [2] 9d 86 [2] 9f 87 [2] 84 81 [2] 98 86 [2] 84 a9 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_4f15 {
  strings:
    $key_4f15 = { 1c 7a [2] 38 74 [2] 13 58 [2] 3d 7a [2] 29 61 [2] 26 7b [2] 38 66 [2] 3a 67 [2] 21 61 [2] 3d 66 [2] 21 49 }

  condition:
    any of them
}
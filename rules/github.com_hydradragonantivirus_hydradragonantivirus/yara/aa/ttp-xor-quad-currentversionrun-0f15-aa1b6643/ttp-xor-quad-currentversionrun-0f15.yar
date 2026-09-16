rule TTP_XOR_QUAD_CurrentVersionRun_0f15 {
  strings:
    $key_0f15 = { 5c 7a [2] 78 74 [2] 53 58 [2] 7d 7a [2] 69 61 [2] 66 7b [2] 78 66 [2] 7a 67 [2] 61 61 [2] 7d 66 [2] 61 49 }

  condition:
    any of them
}
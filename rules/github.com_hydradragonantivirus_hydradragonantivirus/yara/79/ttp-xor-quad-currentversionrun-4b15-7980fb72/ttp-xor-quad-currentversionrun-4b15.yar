rule TTP_XOR_QUAD_CurrentVersionRun_4b15 {
  strings:
    $key_4b15 = { 18 7a [2] 3c 74 [2] 17 58 [2] 39 7a [2] 2d 61 [2] 22 7b [2] 3c 66 [2] 3e 67 [2] 25 61 [2] 39 66 [2] 25 49 }

  condition:
    any of them
}
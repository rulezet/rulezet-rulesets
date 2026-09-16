rule TTP_XOR_QUAD_CurrentVersionRun_1b15 {
  strings:
    $key_1b15 = { 48 7a [2] 6c 74 [2] 47 58 [2] 69 7a [2] 7d 61 [2] 72 7b [2] 6c 66 [2] 6e 67 [2] 75 61 [2] 69 66 [2] 75 49 }

  condition:
    any of them
}
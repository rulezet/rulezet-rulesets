rule TTP_XOR_QUAD_CurrentVersionRun_0f09 {
  strings:
    $key_0f09 = { 5c 66 [2] 78 68 [2] 53 44 [2] 7d 66 [2] 69 7d [2] 66 67 [2] 78 7a [2] 7a 7b [2] 61 7d [2] 7d 7a [2] 61 55 }

  condition:
    any of them
}
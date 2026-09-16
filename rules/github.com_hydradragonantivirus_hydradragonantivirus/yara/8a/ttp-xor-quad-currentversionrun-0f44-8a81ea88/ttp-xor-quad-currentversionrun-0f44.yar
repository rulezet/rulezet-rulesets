rule TTP_XOR_QUAD_CurrentVersionRun_0f44 {
  strings:
    $key_0f44 = { 5c 2b [2] 78 25 [2] 53 09 [2] 7d 2b [2] 69 30 [2] 66 2a [2] 78 37 [2] 7a 36 [2] 61 30 [2] 7d 37 [2] 61 18 }

  condition:
    any of them
}
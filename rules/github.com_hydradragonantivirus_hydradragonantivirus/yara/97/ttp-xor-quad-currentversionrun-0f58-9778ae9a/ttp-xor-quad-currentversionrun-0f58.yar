rule TTP_XOR_QUAD_CurrentVersionRun_0f58 {
  strings:
    $key_0f58 = { 5c 37 [2] 78 39 [2] 53 15 [2] 7d 37 [2] 69 2c [2] 66 36 [2] 78 2b [2] 7a 2a [2] 61 2c [2] 7d 2b [2] 61 04 }

  condition:
    any of them
}
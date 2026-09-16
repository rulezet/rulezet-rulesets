rule TTP_XOR_QUAD_CurrentVersionRun_0f24 {
  strings:
    $key_0f24 = { 5c 4b [2] 78 45 [2] 53 69 [2] 7d 4b [2] 69 50 [2] 66 4a [2] 78 57 [2] 7a 56 [2] 61 50 [2] 7d 57 [2] 61 78 }

  condition:
    any of them
}
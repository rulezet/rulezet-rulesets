rule TTP_XOR_QUAD_CurrentVersionRun_0f36 {
  strings:
    $key_0f36 = { 5c 59 [2] 78 57 [2] 53 7b [2] 7d 59 [2] 69 42 [2] 66 58 [2] 78 45 [2] 7a 44 [2] 61 42 [2] 7d 45 [2] 61 6a }

  condition:
    any of them
}
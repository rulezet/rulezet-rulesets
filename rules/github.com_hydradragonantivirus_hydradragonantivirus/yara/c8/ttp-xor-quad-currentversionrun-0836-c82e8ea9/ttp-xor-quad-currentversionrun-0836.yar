rule TTP_XOR_QUAD_CurrentVersionRun_0836 {
  strings:
    $key_0836 = { 5b 59 [2] 7f 57 [2] 54 7b [2] 7a 59 [2] 6e 42 [2] 61 58 [2] 7f 45 [2] 7d 44 [2] 66 42 [2] 7a 45 [2] 66 6a }

  condition:
    any of them
}
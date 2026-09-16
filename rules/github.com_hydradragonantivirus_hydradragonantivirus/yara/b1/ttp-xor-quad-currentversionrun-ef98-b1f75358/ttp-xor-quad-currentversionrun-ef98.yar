rule TTP_XOR_QUAD_CurrentVersionRun_ef98 {
  strings:
    $key_ef98 = { bc f7 [2] 98 f9 [2] b3 d5 [2] 9d f7 [2] 89 ec [2] 86 f6 [2] 98 eb [2] 9a ea [2] 81 ec [2] 9d eb [2] 81 c4 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_1499 {
  strings:
    $key_1499 = { 47 f6 [2] 63 f8 [2] 48 d4 [2] 66 f6 [2] 72 ed [2] 7d f7 [2] 63 ea [2] 61 eb [2] 7a ed [2] 66 ea [2] 7a c5 }

  condition:
    any of them
}
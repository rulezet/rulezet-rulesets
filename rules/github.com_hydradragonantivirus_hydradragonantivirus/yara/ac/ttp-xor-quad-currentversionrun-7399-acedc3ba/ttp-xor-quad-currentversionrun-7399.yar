rule TTP_XOR_QUAD_CurrentVersionRun_7399 {
  strings:
    $key_7399 = { 20 f6 [2] 04 f8 [2] 2f d4 [2] 01 f6 [2] 15 ed [2] 1a f7 [2] 04 ea [2] 06 eb [2] 1d ed [2] 01 ea [2] 1d c5 }

  condition:
    any of them
}
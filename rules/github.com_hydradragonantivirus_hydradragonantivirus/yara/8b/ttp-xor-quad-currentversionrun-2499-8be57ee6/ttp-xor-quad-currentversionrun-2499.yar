rule TTP_XOR_QUAD_CurrentVersionRun_2499 {
  strings:
    $key_2499 = { 77 f6 [2] 53 f8 [2] 78 d4 [2] 56 f6 [2] 42 ed [2] 4d f7 [2] 53 ea [2] 51 eb [2] 4a ed [2] 56 ea [2] 4a c5 }

  condition:
    any of them
}
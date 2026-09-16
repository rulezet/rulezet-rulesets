rule TTP_XOR_QUAD_CurrentVersionRun_f399 {
  strings:
    $key_f399 = { a0 f6 [2] 84 f8 [2] af d4 [2] 81 f6 [2] 95 ed [2] 9a f7 [2] 84 ea [2] 86 eb [2] 9d ed [2] 81 ea [2] 9d c5 }

  condition:
    any of them
}
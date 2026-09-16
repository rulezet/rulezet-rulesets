rule TTP_XOR_QUAD_CurrentVersionRun_5799 {
  strings:
    $key_5799 = { 04 f6 [2] 20 f8 [2] 0b d4 [2] 25 f6 [2] 31 ed [2] 3e f7 [2] 20 ea [2] 22 eb [2] 39 ed [2] 25 ea [2] 39 c5 }

  condition:
    any of them
}
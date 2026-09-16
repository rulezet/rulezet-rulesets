rule TTP_XOR_QUAD_CurrentVersionRun_6799 {
  strings:
    $key_6799 = { 34 f6 [2] 10 f8 [2] 3b d4 [2] 15 f6 [2] 01 ed [2] 0e f7 [2] 10 ea [2] 12 eb [2] 09 ed [2] 15 ea [2] 09 c5 }

  condition:
    any of them
}
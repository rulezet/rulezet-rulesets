rule TTP_XOR_QUAD_CurrentVersionRun_1699 {
  strings:
    $key_1699 = { 45 f6 [2] 61 f8 [2] 4a d4 [2] 64 f6 [2] 70 ed [2] 7f f7 [2] 61 ea [2] 63 eb [2] 78 ed [2] 64 ea [2] 78 c5 }

  condition:
    any of them
}
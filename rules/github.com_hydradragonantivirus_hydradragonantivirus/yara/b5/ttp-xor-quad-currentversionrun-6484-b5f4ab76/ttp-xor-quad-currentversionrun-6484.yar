rule TTP_XOR_QUAD_CurrentVersionRun_6484 {
  strings:
    $key_6484 = { 37 eb [2] 13 e5 [2] 38 c9 [2] 16 eb [2] 02 f0 [2] 0d ea [2] 13 f7 [2] 11 f6 [2] 0a f0 [2] 16 f7 [2] 0a d8 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_4484 {
  strings:
    $key_4484 = { 17 eb [2] 33 e5 [2] 18 c9 [2] 36 eb [2] 22 f0 [2] 2d ea [2] 33 f7 [2] 31 f6 [2] 2a f0 [2] 36 f7 [2] 2a d8 }

  condition:
    any of them
}
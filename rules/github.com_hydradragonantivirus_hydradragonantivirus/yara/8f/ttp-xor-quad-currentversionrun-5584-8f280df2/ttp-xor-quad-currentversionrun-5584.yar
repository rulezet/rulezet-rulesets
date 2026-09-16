rule TTP_XOR_QUAD_CurrentVersionRun_5584 {
  strings:
    $key_5584 = { 06 eb [2] 22 e5 [2] 09 c9 [2] 27 eb [2] 33 f0 [2] 3c ea [2] 22 f7 [2] 20 f6 [2] 3b f0 [2] 27 f7 [2] 3b d8 }

  condition:
    any of them
}
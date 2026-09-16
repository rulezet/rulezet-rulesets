rule TTP_XOR_QUAD_CurrentVersionRun_7584 {
  strings:
    $key_7584 = { 26 eb [2] 02 e5 [2] 29 c9 [2] 07 eb [2] 13 f0 [2] 1c ea [2] 02 f7 [2] 00 f6 [2] 1b f0 [2] 07 f7 [2] 1b d8 }

  condition:
    any of them
}
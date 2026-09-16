rule TTP_XOR_QUAD_CurrentVersionRun_1584 {
  strings:
    $key_1584 = { 46 eb [2] 62 e5 [2] 49 c9 [2] 67 eb [2] 73 f0 [2] 7c ea [2] 62 f7 [2] 60 f6 [2] 7b f0 [2] 67 f7 [2] 7b d8 }

  condition:
    any of them
}
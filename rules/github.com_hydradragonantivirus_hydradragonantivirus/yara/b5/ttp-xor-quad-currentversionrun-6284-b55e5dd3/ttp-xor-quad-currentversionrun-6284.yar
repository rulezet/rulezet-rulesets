rule TTP_XOR_QUAD_CurrentVersionRun_6284 {
  strings:
    $key_6284 = { 31 eb [2] 15 e5 [2] 3e c9 [2] 10 eb [2] 04 f0 [2] 0b ea [2] 15 f7 [2] 17 f6 [2] 0c f0 [2] 10 f7 [2] 0c d8 }

  condition:
    any of them
}
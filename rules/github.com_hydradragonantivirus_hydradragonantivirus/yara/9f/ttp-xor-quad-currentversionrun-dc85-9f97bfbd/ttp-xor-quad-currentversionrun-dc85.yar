rule TTP_XOR_QUAD_CurrentVersionRun_dc85 {
  strings:
    $key_dc85 = { 8f ea [2] ab e4 [2] 80 c8 [2] ae ea [2] ba f1 [2] b5 eb [2] ab f6 [2] a9 f7 [2] b2 f1 [2] ae f6 [2] b2 d9 }

  condition:
    any of them
}
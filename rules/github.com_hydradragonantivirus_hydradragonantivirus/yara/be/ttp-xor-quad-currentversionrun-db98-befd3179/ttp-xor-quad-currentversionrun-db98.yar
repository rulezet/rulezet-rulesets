rule TTP_XOR_QUAD_CurrentVersionRun_db98 {
  strings:
    $key_db98 = { 88 f7 [2] ac f9 [2] 87 d5 [2] a9 f7 [2] bd ec [2] b2 f6 [2] ac eb [2] ae ea [2] b5 ec [2] a9 eb [2] b5 c4 }

  condition:
    any of them
}
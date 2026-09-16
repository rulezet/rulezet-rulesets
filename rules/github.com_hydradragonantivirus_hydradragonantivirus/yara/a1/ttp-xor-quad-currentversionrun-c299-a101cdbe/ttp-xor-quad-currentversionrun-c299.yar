rule TTP_XOR_QUAD_CurrentVersionRun_c299 {
  strings:
    $key_c299 = { 91 f6 [2] b5 f8 [2] 9e d4 [2] b0 f6 [2] a4 ed [2] ab f7 [2] b5 ea [2] b7 eb [2] ac ed [2] b0 ea [2] ac c5 }

  condition:
    any of them
}
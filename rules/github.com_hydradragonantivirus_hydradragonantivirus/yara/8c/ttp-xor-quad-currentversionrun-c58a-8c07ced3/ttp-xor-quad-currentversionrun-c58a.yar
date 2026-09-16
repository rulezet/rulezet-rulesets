rule TTP_XOR_QUAD_CurrentVersionRun_c58a {
  strings:
    $key_c58a = { 96 e5 [2] b2 eb [2] 99 c7 [2] b7 e5 [2] a3 fe [2] ac e4 [2] b2 f9 [2] b0 f8 [2] ab fe [2] b7 f9 [2] ab d6 }

  condition:
    any of them
}
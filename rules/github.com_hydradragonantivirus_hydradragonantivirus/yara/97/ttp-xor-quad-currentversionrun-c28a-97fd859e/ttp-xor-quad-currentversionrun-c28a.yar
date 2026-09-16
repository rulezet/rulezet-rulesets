rule TTP_XOR_QUAD_CurrentVersionRun_c28a {
  strings:
    $key_c28a = { 91 e5 [2] b5 eb [2] 9e c7 [2] b0 e5 [2] a4 fe [2] ab e4 [2] b5 f9 [2] b7 f8 [2] ac fe [2] b0 f9 [2] ac d6 }

  condition:
    any of them
}
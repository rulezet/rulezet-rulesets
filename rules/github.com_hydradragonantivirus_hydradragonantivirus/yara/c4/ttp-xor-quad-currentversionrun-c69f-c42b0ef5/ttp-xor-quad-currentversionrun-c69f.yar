rule TTP_XOR_QUAD_CurrentVersionRun_c69f {
  strings:
    $key_c69f = { 95 f0 [2] b1 fe [2] 9a d2 [2] b4 f0 [2] a0 eb [2] af f1 [2] b1 ec [2] b3 ed [2] a8 eb [2] b4 ec [2] a8 c3 }

  condition:
    any of them
}
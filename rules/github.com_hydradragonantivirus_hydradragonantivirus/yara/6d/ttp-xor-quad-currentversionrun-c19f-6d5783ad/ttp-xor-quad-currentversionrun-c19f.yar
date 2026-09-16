rule TTP_XOR_QUAD_CurrentVersionRun_c19f {
  strings:
    $key_c19f = { 92 f0 [2] b6 fe [2] 9d d2 [2] b3 f0 [2] a7 eb [2] a8 f1 [2] b6 ec [2] b4 ed [2] af eb [2] b3 ec [2] af c3 }

  condition:
    any of them
}
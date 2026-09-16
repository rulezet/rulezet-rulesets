rule TTP_XOR_QUAD_CurrentVersionRun_c28d {
  strings:
    $key_c28d = { 91 e2 [2] b5 ec [2] 9e c0 [2] b0 e2 [2] a4 f9 [2] ab e3 [2] b5 fe [2] b7 ff [2] ac f9 [2] b0 fe [2] ac d1 }

  condition:
    any of them
}
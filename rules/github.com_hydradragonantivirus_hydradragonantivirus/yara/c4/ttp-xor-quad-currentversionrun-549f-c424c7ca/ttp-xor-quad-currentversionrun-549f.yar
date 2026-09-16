rule TTP_XOR_QUAD_CurrentVersionRun_549f {
  strings:
    $key_549f = { 07 f0 [2] 23 fe [2] 08 d2 [2] 26 f0 [2] 32 eb [2] 3d f1 [2] 23 ec [2] 21 ed [2] 3a eb [2] 26 ec [2] 3a c3 }

  condition:
    any of them
}
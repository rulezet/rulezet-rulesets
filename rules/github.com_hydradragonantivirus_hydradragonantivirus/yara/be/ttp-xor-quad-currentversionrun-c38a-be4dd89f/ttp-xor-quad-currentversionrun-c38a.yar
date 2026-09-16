rule TTP_XOR_QUAD_CurrentVersionRun_c38a {
  strings:
    $key_c38a = { 90 e5 [2] b4 eb [2] 9f c7 [2] b1 e5 [2] a5 fe [2] aa e4 [2] b4 f9 [2] b6 f8 [2] ad fe [2] b1 f9 [2] ad d6 }

  condition:
    any of them
}
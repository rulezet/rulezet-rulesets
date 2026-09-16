rule TTP_XOR_QUAD_CurrentVersionRun_cc8a {
  strings:
    $key_cc8a = { 9f e5 [2] bb eb [2] 90 c7 [2] be e5 [2] aa fe [2] a5 e4 [2] bb f9 [2] b9 f8 [2] a2 fe [2] be f9 [2] a2 d6 }

  condition:
    any of them
}
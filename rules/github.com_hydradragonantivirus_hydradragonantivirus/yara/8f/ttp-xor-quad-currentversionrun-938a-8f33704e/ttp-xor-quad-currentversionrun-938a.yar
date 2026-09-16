rule TTP_XOR_QUAD_CurrentVersionRun_938a {
  strings:
    $key_938a = { c0 e5 [2] e4 eb [2] cf c7 [2] e1 e5 [2] f5 fe [2] fa e4 [2] e4 f9 [2] e6 f8 [2] fd fe [2] e1 f9 [2] fd d6 }

  condition:
    any of them
}
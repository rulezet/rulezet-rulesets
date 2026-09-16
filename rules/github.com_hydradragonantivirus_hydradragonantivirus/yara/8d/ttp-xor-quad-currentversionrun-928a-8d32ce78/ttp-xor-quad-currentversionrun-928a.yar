rule TTP_XOR_QUAD_CurrentVersionRun_928a {
  strings:
    $key_928a = { c1 e5 [2] e5 eb [2] ce c7 [2] e0 e5 [2] f4 fe [2] fb e4 [2] e5 f9 [2] e7 f8 [2] fc fe [2] e0 f9 [2] fc d6 }

  condition:
    any of them
}
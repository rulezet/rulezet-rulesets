rule TTP_XOR_QUAD_CurrentVersionRun_a18a {
  strings:
    $key_a18a = { f2 e5 [2] d6 eb [2] fd c7 [2] d3 e5 [2] c7 fe [2] c8 e4 [2] d6 f9 [2] d4 f8 [2] cf fe [2] d3 f9 [2] cf d6 }

  condition:
    any of them
}
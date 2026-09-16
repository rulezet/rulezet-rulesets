rule TTP_XOR_QUAD_CurrentVersionRun_a18d {
  strings:
    $key_a18d = { f2 e2 [2] d6 ec [2] fd c0 [2] d3 e2 [2] c7 f9 [2] c8 e3 [2] d6 fe [2] d4 ff [2] cf f9 [2] d3 fe [2] cf d1 }

  condition:
    any of them
}
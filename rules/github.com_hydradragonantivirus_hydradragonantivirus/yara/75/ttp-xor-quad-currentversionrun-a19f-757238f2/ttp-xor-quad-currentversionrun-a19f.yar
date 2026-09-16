rule TTP_XOR_QUAD_CurrentVersionRun_a19f {
  strings:
    $key_a19f = { f2 f0 [2] d6 fe [2] fd d2 [2] d3 f0 [2] c7 eb [2] c8 f1 [2] d6 ec [2] d4 ed [2] cf eb [2] d3 ec [2] cf c3 }

  condition:
    any of them
}
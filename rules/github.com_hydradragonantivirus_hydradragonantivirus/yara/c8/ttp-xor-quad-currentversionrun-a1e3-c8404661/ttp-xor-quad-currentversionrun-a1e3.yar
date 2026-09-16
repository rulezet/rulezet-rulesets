rule TTP_XOR_QUAD_CurrentVersionRun_a1e3 {
  strings:
    $key_a1e3 = { f2 8c [2] d6 82 [2] fd ae [2] d3 8c [2] c7 97 [2] c8 8d [2] d6 90 [2] d4 91 [2] cf 97 [2] d3 90 [2] cf bf }

  condition:
    any of them
}
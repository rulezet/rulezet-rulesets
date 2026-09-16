rule TTP_XOR_QUAD_CurrentVersionRun_b06b {
  strings:
    $key_b06b = { e3 04 [2] c7 0a [2] ec 26 [2] c2 04 [2] d6 1f [2] d9 05 [2] c7 18 [2] c5 19 [2] de 1f [2] c2 18 [2] de 37 }

  condition:
    any of them
}
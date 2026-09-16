rule TTP_XOR_QUAD_CurrentVersionRun_b04b {
  strings:
    $key_b04b = { e3 24 [2] c7 2a [2] ec 06 [2] c2 24 [2] d6 3f [2] d9 25 [2] c7 38 [2] c5 39 [2] de 3f [2] c2 38 [2] de 17 }

  condition:
    any of them
}
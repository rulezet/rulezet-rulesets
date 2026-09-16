rule TTP_XOR_QUAD_CurrentVersionRun_b071 {
  strings:
    $key_b071 = { e3 1e [2] c7 10 [2] ec 3c [2] c2 1e [2] d6 05 [2] d9 1f [2] c7 02 [2] c5 03 [2] de 05 [2] c2 02 [2] de 2d }

  condition:
    any of them
}
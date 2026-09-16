rule TTP_XOR_QUAD_CurrentVersionRun_b07c {
  strings:
    $key_b07c = { e3 13 [2] c7 1d [2] ec 31 [2] c2 13 [2] d6 08 [2] d9 12 [2] c7 0f [2] c5 0e [2] de 08 [2] c2 0f [2] de 20 }

  condition:
    any of them
}
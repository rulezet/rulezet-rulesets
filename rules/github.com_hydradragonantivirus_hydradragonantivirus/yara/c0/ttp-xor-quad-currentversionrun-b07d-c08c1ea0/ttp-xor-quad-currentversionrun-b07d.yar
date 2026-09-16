rule TTP_XOR_QUAD_CurrentVersionRun_b07d {
  strings:
    $key_b07d = { e3 12 [2] c7 1c [2] ec 30 [2] c2 12 [2] d6 09 [2] d9 13 [2] c7 0e [2] c5 0f [2] de 09 [2] c2 0e [2] de 21 }

  condition:
    any of them
}
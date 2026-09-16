rule TTP_XOR_QUAD_CurrentVersionRun_b001 {
  strings:
    $key_b001 = { e3 6e [2] c7 60 [2] ec 4c [2] c2 6e [2] d6 75 [2] d9 6f [2] c7 72 [2] c5 73 [2] de 75 [2] c2 72 [2] de 5d }

  condition:
    any of them
}
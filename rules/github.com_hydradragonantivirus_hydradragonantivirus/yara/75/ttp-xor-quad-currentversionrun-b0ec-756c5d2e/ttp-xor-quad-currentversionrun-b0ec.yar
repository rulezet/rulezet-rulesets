rule TTP_XOR_QUAD_CurrentVersionRun_b0ec {
  strings:
    $key_b0ec = { e3 83 [2] c7 8d [2] ec a1 [2] c2 83 [2] d6 98 [2] d9 82 [2] c7 9f [2] c5 9e [2] de 98 [2] c2 9f [2] de b0 }

  condition:
    any of them
}
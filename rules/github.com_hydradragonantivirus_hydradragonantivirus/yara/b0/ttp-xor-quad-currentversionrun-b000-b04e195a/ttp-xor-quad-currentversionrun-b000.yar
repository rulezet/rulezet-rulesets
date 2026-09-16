rule TTP_XOR_QUAD_CurrentVersionRun_b000 {
  strings:
    $key_b000 = { e3 6f [2] c7 61 [2] ec 4d [2] c2 6f [2] d6 74 [2] d9 6e [2] c7 73 [2] c5 72 [2] de 74 [2] c2 73 [2] de 5c }

  condition:
    any of them
}
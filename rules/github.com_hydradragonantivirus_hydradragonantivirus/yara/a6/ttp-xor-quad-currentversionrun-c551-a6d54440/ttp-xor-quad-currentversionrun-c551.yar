rule TTP_XOR_QUAD_CurrentVersionRun_c551 {
  strings:
    $key_c551 = { 96 3e [2] b2 30 [2] 99 1c [2] b7 3e [2] a3 25 [2] ac 3f [2] b2 22 [2] b0 23 [2] ab 25 [2] b7 22 [2] ab 0d }

  condition:
    any of them
}
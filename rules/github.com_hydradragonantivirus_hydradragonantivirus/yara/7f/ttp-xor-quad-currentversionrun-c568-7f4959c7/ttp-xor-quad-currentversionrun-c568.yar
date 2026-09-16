rule TTP_XOR_QUAD_CurrentVersionRun_c568 {
  strings:
    $key_c568 = { 96 07 [2] b2 09 [2] 99 25 [2] b7 07 [2] a3 1c [2] ac 06 [2] b2 1b [2] b0 1a [2] ab 1c [2] b7 1b [2] ab 34 }

  condition:
    any of them
}
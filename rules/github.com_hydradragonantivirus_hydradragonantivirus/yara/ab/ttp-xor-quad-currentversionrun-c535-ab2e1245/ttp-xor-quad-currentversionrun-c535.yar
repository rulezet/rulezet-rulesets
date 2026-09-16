rule TTP_XOR_QUAD_CurrentVersionRun_c535 {
  strings:
    $key_c535 = { 96 5a [2] b2 54 [2] 99 78 [2] b7 5a [2] a3 41 [2] ac 5b [2] b2 46 [2] b0 47 [2] ab 41 [2] b7 46 [2] ab 69 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_c536 {
  strings:
    $key_c536 = { 96 59 [2] b2 57 [2] 99 7b [2] b7 59 [2] a3 42 [2] ac 58 [2] b2 45 [2] b0 44 [2] ab 42 [2] b7 45 [2] ab 6a }

  condition:
    any of them
}
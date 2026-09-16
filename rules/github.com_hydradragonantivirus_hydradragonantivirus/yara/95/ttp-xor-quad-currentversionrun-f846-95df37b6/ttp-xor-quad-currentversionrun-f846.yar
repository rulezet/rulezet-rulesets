rule TTP_XOR_QUAD_CurrentVersionRun_f846 {
  strings:
    $key_f846 = { ab 29 [2] 8f 27 [2] a4 0b [2] 8a 29 [2] 9e 32 [2] 91 28 [2] 8f 35 [2] 8d 34 [2] 96 32 [2] 8a 35 [2] 96 1a }

  condition:
    any of them
}
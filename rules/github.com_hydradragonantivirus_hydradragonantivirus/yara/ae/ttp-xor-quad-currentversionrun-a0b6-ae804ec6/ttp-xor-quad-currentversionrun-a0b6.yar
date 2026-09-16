rule TTP_XOR_QUAD_CurrentVersionRun_a0b6 {
  strings:
    $key_a0b6 = { f3 d9 [2] d7 d7 [2] fc fb [2] d2 d9 [2] c6 c2 [2] c9 d8 [2] d7 c5 [2] d5 c4 [2] ce c2 [2] d2 c5 [2] ce ea }

  condition:
    any of them
}
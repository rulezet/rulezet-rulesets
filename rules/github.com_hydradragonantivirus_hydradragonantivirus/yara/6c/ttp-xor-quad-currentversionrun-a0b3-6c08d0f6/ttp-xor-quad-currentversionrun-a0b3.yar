rule TTP_XOR_QUAD_CurrentVersionRun_a0b3 {
  strings:
    $key_a0b3 = { f3 dc [2] d7 d2 [2] fc fe [2] d2 dc [2] c6 c7 [2] c9 dd [2] d7 c0 [2] d5 c1 [2] ce c7 [2] d2 c0 [2] ce ef }

  condition:
    any of them
}
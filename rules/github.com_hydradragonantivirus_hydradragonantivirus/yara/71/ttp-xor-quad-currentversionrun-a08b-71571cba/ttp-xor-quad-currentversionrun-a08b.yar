rule TTP_XOR_QUAD_CurrentVersionRun_a08b {
  strings:
    $key_a08b = { f3 e4 [2] d7 ea [2] fc c6 [2] d2 e4 [2] c6 ff [2] c9 e5 [2] d7 f8 [2] d5 f9 [2] ce ff [2] d2 f8 [2] ce d7 }

  condition:
    any of them
}
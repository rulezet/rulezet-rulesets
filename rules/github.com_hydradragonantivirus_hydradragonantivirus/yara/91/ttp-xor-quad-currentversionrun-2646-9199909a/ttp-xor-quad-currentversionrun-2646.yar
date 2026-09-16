rule TTP_XOR_QUAD_CurrentVersionRun_2646 {
  strings:
    $key_2646 = { 75 29 [2] 51 27 [2] 7a 0b [2] 54 29 [2] 40 32 [2] 4f 28 [2] 51 35 [2] 53 34 [2] 48 32 [2] 54 35 [2] 48 1a }

  condition:
    any of them
}
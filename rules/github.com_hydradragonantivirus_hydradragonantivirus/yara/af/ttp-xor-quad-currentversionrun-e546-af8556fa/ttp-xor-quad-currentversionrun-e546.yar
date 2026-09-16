rule TTP_XOR_QUAD_CurrentVersionRun_e546 {
  strings:
    $key_e546 = { b6 29 [2] 92 27 [2] b9 0b [2] 97 29 [2] 83 32 [2] 8c 28 [2] 92 35 [2] 90 34 [2] 8b 32 [2] 97 35 [2] 8b 1a }

  condition:
    any of them
}
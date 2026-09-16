rule TTP_XOR_QUAD_CurrentVersionRun_4026 {
  strings:
    $key_4026 = { 13 49 [2] 37 47 [2] 1c 6b [2] 32 49 [2] 26 52 [2] 29 48 [2] 37 55 [2] 35 54 [2] 2e 52 [2] 32 55 [2] 2e 7a }

  condition:
    any of them
}
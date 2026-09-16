rule TTP_XOR_QUAD_CurrentVersionRun_40f9 {
  strings:
    $key_40f9 = { 13 96 [2] 37 98 [2] 1c b4 [2] 32 96 [2] 26 8d [2] 29 97 [2] 37 8a [2] 35 8b [2] 2e 8d [2] 32 8a [2] 2e a5 }

  condition:
    any of them
}
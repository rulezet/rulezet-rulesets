rule TTP_XOR_QUAD_CurrentVersionRun_4034 {
  strings:
    $key_4034 = { 13 5b [2] 37 55 [2] 1c 79 [2] 32 5b [2] 26 40 [2] 29 5a [2] 37 47 [2] 35 46 [2] 2e 40 [2] 32 47 [2] 2e 68 }

  condition:
    any of them
}
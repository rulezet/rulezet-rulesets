rule TTP_XOR_QUAD_CurrentVersionRun_47d9 {
  strings:
    $key_47d9 = { 14 b6 [2] 30 b8 [2] 1b 94 [2] 35 b6 [2] 21 ad [2] 2e b7 [2] 30 aa [2] 32 ab [2] 29 ad [2] 35 aa [2] 29 85 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_10c4 {
  strings:
    $key_10c4 = { 43 ab [2] 67 a5 [2] 4c 89 [2] 62 ab [2] 76 b0 [2] 79 aa [2] 67 b7 [2] 65 b6 [2] 7e b0 [2] 62 b7 [2] 7e 98 }

  condition:
    any of them
}
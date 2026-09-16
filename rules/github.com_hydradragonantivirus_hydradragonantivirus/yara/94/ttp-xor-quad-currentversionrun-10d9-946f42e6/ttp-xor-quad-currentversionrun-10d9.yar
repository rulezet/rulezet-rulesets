rule TTP_XOR_QUAD_CurrentVersionRun_10d9 {
  strings:
    $key_10d9 = { 43 b6 [2] 67 b8 [2] 4c 94 [2] 62 b6 [2] 76 ad [2] 79 b7 [2] 67 aa [2] 65 ab [2] 7e ad [2] 62 aa [2] 7e 85 }

  condition:
    any of them
}
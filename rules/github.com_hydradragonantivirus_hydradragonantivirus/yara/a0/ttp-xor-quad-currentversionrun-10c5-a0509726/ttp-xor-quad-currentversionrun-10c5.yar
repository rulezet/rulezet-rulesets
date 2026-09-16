rule TTP_XOR_QUAD_CurrentVersionRun_10c5 {
  strings:
    $key_10c5 = { 43 aa [2] 67 a4 [2] 4c 88 [2] 62 aa [2] 76 b1 [2] 79 ab [2] 67 b6 [2] 65 b7 [2] 7e b1 [2] 62 b6 [2] 7e 99 }

  condition:
    any of them
}
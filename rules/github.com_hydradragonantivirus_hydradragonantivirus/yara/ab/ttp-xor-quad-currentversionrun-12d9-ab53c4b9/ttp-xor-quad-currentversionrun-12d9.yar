rule TTP_XOR_QUAD_CurrentVersionRun_12d9 {
  strings:
    $key_12d9 = { 41 b6 [2] 65 b8 [2] 4e 94 [2] 60 b6 [2] 74 ad [2] 7b b7 [2] 65 aa [2] 67 ab [2] 7c ad [2] 60 aa [2] 7c 85 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_20c4 {
  strings:
    $key_20c4 = { 73 ab [2] 57 a5 [2] 7c 89 [2] 52 ab [2] 46 b0 [2] 49 aa [2] 57 b7 [2] 55 b6 [2] 4e b0 [2] 52 b7 [2] 4e 98 }

  condition:
    any of them
}
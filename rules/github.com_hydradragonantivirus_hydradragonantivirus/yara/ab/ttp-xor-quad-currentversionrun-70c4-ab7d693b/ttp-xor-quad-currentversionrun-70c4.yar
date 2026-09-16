rule TTP_XOR_QUAD_CurrentVersionRun_70c4 {
  strings:
    $key_70c4 = { 23 ab [2] 07 a5 [2] 2c 89 [2] 02 ab [2] 16 b0 [2] 19 aa [2] 07 b7 [2] 05 b6 [2] 1e b0 [2] 02 b7 [2] 1e 98 }

  condition:
    any of them
}
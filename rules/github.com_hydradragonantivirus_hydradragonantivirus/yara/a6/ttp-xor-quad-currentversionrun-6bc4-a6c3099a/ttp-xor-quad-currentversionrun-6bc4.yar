rule TTP_XOR_QUAD_CurrentVersionRun_6bc4 {
  strings:
    $key_6bc4 = { 38 ab [2] 1c a5 [2] 37 89 [2] 19 ab [2] 0d b0 [2] 02 aa [2] 1c b7 [2] 1e b6 [2] 05 b0 [2] 19 b7 [2] 05 98 }

  condition:
    any of them
}
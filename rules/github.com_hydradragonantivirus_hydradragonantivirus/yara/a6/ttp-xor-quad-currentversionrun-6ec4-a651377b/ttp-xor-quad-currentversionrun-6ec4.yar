rule TTP_XOR_QUAD_CurrentVersionRun_6ec4 {
  strings:
    $key_6ec4 = { 3d ab [2] 19 a5 [2] 32 89 [2] 1c ab [2] 08 b0 [2] 07 aa [2] 19 b7 [2] 1b b6 [2] 00 b0 [2] 1c b7 [2] 00 98 }

  condition:
    any of them
}
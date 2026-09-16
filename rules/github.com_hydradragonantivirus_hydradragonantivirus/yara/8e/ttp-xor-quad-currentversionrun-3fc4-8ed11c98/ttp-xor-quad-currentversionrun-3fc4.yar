rule TTP_XOR_QUAD_CurrentVersionRun_3fc4 {
  strings:
    $key_3fc4 = { 6c ab [2] 48 a5 [2] 63 89 [2] 4d ab [2] 59 b0 [2] 56 aa [2] 48 b7 [2] 4a b6 [2] 51 b0 [2] 4d b7 [2] 51 98 }

  condition:
    any of them
}
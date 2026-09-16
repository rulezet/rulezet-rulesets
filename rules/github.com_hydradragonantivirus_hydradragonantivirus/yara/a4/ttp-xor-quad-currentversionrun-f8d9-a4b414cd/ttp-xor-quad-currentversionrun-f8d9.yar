rule TTP_XOR_QUAD_CurrentVersionRun_f8d9 {
  strings:
    $key_f8d9 = { ab b6 [2] 8f b8 [2] a4 94 [2] 8a b6 [2] 9e ad [2] 91 b7 [2] 8f aa [2] 8d ab [2] 96 ad [2] 8a aa [2] 96 85 }

  condition:
    any of them
}
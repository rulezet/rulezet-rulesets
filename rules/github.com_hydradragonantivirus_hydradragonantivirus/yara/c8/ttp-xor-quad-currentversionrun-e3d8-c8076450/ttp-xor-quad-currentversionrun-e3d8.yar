rule TTP_XOR_QUAD_CurrentVersionRun_e3d8 {
  strings:
    $key_e3d8 = { b0 b7 [2] 94 b9 [2] bf 95 [2] 91 b7 [2] 85 ac [2] 8a b6 [2] 94 ab [2] 96 aa [2] 8d ac [2] 91 ab [2] 8d 84 }

  condition:
    any of them
}
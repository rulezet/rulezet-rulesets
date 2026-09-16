rule TTP_XOR_QUAD_CurrentVersionRun_61d8 {
  strings:
    $key_61d8 = { 32 b7 [2] 16 b9 [2] 3d 95 [2] 13 b7 [2] 07 ac [2] 08 b6 [2] 16 ab [2] 14 aa [2] 0f ac [2] 13 ab [2] 0f 84 }

  condition:
    any of them
}
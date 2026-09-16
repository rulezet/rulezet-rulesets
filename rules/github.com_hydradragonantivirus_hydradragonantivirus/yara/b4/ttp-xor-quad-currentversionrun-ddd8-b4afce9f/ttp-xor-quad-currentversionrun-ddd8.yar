rule TTP_XOR_QUAD_CurrentVersionRun_ddd8 {
  strings:
    $key_ddd8 = { 8e b7 [2] aa b9 [2] 81 95 [2] af b7 [2] bb ac [2] b4 b6 [2] aa ab [2] a8 aa [2] b3 ac [2] af ab [2] b3 84 }

  condition:
    any of them
}
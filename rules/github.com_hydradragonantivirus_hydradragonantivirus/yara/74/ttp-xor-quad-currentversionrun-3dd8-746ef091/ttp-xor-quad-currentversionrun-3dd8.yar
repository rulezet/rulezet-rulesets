rule TTP_XOR_QUAD_CurrentVersionRun_3dd8 {
  strings:
    $key_3dd8 = { 6e b7 [2] 4a b9 [2] 61 95 [2] 4f b7 [2] 5b ac [2] 54 b6 [2] 4a ab [2] 48 aa [2] 53 ac [2] 4f ab [2] 53 84 }

  condition:
    any of them
}
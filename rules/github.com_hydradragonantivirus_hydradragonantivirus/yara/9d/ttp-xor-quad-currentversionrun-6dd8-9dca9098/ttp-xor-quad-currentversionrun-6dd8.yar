rule TTP_XOR_QUAD_CurrentVersionRun_6dd8 {
  strings:
    $key_6dd8 = { 3e b7 [2] 1a b9 [2] 31 95 [2] 1f b7 [2] 0b ac [2] 04 b6 [2] 1a ab [2] 18 aa [2] 03 ac [2] 1f ab [2] 03 84 }

  condition:
    any of them
}
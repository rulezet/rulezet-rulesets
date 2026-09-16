rule TTP_XOR_QUAD_CurrentVersionRun_e8d8 {
  strings:
    $key_e8d8 = { bb b7 [2] 9f b9 [2] b4 95 [2] 9a b7 [2] 8e ac [2] 81 b6 [2] 9f ab [2] 9d aa [2] 86 ac [2] 9a ab [2] 86 84 }

  condition:
    any of them
}
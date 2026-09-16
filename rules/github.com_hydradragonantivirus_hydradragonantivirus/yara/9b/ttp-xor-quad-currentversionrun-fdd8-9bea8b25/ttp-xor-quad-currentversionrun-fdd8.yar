rule TTP_XOR_QUAD_CurrentVersionRun_fdd8 {
  strings:
    $key_fdd8 = { ae b7 [2] 8a b9 [2] a1 95 [2] 8f b7 [2] 9b ac [2] 94 b6 [2] 8a ab [2] 88 aa [2] 93 ac [2] 8f ab [2] 93 84 }

  condition:
    any of them
}
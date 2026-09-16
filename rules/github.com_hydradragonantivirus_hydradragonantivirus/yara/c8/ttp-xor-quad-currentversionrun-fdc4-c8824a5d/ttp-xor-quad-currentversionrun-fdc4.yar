rule TTP_XOR_QUAD_CurrentVersionRun_fdc4 {
  strings:
    $key_fdc4 = { ae ab [2] 8a a5 [2] a1 89 [2] 8f ab [2] 9b b0 [2] 94 aa [2] 8a b7 [2] 88 b6 [2] 93 b0 [2] 8f b7 [2] 93 98 }

  condition:
    any of them
}
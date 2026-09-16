rule TTP_XOR_QUAD_CurrentVersionRun_fe99 {
  strings:
    $key_fe99 = { ad f6 [2] 89 f8 [2] a2 d4 [2] 8c f6 [2] 98 ed [2] 97 f7 [2] 89 ea [2] 8b eb [2] 90 ed [2] 8c ea [2] 90 c5 }

  condition:
    any of them
}
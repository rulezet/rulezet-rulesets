rule TTP_XOR_QUAD_CurrentVersionRun_b2eb {
  strings:
    $key_b2eb = { e1 84 [2] c5 8a [2] ee a6 [2] c0 84 [2] d4 9f [2] db 85 [2] c5 98 [2] c7 99 [2] dc 9f [2] c0 98 [2] dc b7 }

  condition:
    any of them
}
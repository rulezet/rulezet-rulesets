rule TTP_XOR_QUAD_CurrentVersionRun_ad8c {
  strings:
    $key_ad8c = { fe e3 [2] da ed [2] f1 c1 [2] df e3 [2] cb f8 [2] c4 e2 [2] da ff [2] d8 fe [2] c3 f8 [2] df ff [2] c3 d0 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_b6b9 {
  strings:
    $key_b6b9 = { e5 d6 [2] c1 d8 [2] ea f4 [2] c4 d6 [2] d0 cd [2] df d7 [2] c1 ca [2] c3 cb [2] d8 cd [2] c4 ca [2] d8 e5 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_b1b8 {
  strings:
    $key_b1b8 = { e2 d7 [2] c6 d9 [2] ed f5 [2] c3 d7 [2] d7 cc [2] d8 d6 [2] c6 cb [2] c4 ca [2] df cc [2] c3 cb [2] df e4 }

  condition:
    any of them
}
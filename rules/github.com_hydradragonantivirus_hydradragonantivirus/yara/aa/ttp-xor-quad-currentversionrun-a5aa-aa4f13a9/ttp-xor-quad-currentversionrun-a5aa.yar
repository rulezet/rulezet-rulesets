rule TTP_XOR_QUAD_CurrentVersionRun_a5aa {
  strings:
    $key_a5aa = { f6 c5 [2] d2 cb [2] f9 e7 [2] d7 c5 [2] c3 de [2] cc c4 [2] d2 d9 [2] d0 d8 [2] cb de [2] d7 d9 [2] cb f6 }

  condition:
    any of them
}
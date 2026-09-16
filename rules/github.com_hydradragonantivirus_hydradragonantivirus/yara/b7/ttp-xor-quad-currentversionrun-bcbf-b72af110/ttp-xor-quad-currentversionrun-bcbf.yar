rule TTP_XOR_QUAD_CurrentVersionRun_bcbf {
  strings:
    $key_bcbf = { ef d0 [2] cb de [2] e0 f2 [2] ce d0 [2] da cb [2] d5 d1 [2] cb cc [2] c9 cd [2] d2 cb [2] ce cc [2] d2 e3 }

  condition:
    any of them
}
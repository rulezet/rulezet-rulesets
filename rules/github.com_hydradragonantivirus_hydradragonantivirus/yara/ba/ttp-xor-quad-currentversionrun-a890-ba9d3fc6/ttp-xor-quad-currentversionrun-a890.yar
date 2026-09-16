rule TTP_XOR_QUAD_CurrentVersionRun_a890 {
  strings:
    $key_a890 = { fb ff [2] df f1 [2] f4 dd [2] da ff [2] ce e4 [2] c1 fe [2] df e3 [2] dd e2 [2] c6 e4 [2] da e3 [2] c6 cc }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_8890 {
  strings:
    $key_8890 = { db ff [2] ff f1 [2] d4 dd [2] fa ff [2] ee e4 [2] e1 fe [2] ff e3 [2] fd e2 [2] e6 e4 [2] fa e3 [2] e6 cc }

  condition:
    any of them
}
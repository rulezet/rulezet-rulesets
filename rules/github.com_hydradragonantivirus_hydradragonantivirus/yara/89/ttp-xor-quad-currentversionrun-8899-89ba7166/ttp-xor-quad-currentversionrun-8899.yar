rule TTP_XOR_QUAD_CurrentVersionRun_8899 {
  strings:
    $key_8899 = { db f6 [2] ff f8 [2] d4 d4 [2] fa f6 [2] ee ed [2] e1 f7 [2] ff ea [2] fd eb [2] e6 ed [2] fa ea [2] e6 c5 }

  condition:
    any of them
}
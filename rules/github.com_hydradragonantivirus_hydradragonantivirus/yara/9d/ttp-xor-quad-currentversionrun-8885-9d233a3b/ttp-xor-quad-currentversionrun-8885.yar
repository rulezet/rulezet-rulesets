rule TTP_XOR_QUAD_CurrentVersionRun_8885 {
  strings:
    $key_8885 = { db ea [2] ff e4 [2] d4 c8 [2] fa ea [2] ee f1 [2] e1 eb [2] ff f6 [2] fd f7 [2] e6 f1 [2] fa f6 [2] e6 d9 }

  condition:
    any of them
}
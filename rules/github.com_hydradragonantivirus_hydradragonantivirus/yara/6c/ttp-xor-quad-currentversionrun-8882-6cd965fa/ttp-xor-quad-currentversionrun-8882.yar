rule TTP_XOR_QUAD_CurrentVersionRun_8882 {
  strings:
    $key_8882 = { db ed [2] ff e3 [2] d4 cf [2] fa ed [2] ee f6 [2] e1 ec [2] ff f1 [2] fd f0 [2] e6 f6 [2] fa f1 [2] e6 de }

  condition:
    any of them
}
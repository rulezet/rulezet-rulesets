rule TTP_XOR_QUAD_CurrentVersionRun_b352 {
  strings:
    $key_b352 = { e0 3d [2] c4 33 [2] ef 1f [2] c1 3d [2] d5 26 [2] da 3c [2] c4 21 [2] c6 20 [2] dd 26 [2] c1 21 [2] dd 0e }

  condition:
    any of them
}
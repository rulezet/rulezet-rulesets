rule TTP_XOR_QUAD_CurrentVersionRun_8d90 {
  strings:
    $key_8d90 = { de ff [2] fa f1 [2] d1 dd [2] ff ff [2] eb e4 [2] e4 fe [2] fa e3 [2] f8 e2 [2] e3 e4 [2] ff e3 [2] e3 cc }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_ee90 {
  strings:
    $key_ee90 = { bd ff [2] 99 f1 [2] b2 dd [2] 9c ff [2] 88 e4 [2] 87 fe [2] 99 e3 [2] 9b e2 [2] 80 e4 [2] 9c e3 [2] 80 cc }

  condition:
    any of them
}
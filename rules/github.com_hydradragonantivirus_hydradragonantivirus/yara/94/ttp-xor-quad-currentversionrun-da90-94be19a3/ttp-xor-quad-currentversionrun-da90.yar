rule TTP_XOR_QUAD_CurrentVersionRun_da90 {
  strings:
    $key_da90 = { 89 ff [2] ad f1 [2] 86 dd [2] a8 ff [2] bc e4 [2] b3 fe [2] ad e3 [2] af e2 [2] b4 e4 [2] a8 e3 [2] b4 cc }

  condition:
    any of them
}
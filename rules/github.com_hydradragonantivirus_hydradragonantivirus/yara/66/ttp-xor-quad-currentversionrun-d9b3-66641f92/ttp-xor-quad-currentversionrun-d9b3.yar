rule TTP_XOR_QUAD_CurrentVersionRun_d9b3 {
  strings:
    $key_d9b3 = { 8a dc [2] ae d2 [2] 85 fe [2] ab dc [2] bf c7 [2] b0 dd [2] ae c0 [2] ac c1 [2] b7 c7 [2] ab c0 [2] b7 ef }

  condition:
    any of them
}
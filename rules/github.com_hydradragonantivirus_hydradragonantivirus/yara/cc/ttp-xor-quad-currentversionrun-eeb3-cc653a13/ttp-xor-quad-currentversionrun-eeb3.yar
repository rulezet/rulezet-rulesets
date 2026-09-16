rule TTP_XOR_QUAD_CurrentVersionRun_eeb3 {
  strings:
    $key_eeb3 = { bd dc [2] 99 d2 [2] b2 fe [2] 9c dc [2] 88 c7 [2] 87 dd [2] 99 c0 [2] 9b c1 [2] 80 c7 [2] 9c c0 [2] 80 ef }

  condition:
    any of them
}
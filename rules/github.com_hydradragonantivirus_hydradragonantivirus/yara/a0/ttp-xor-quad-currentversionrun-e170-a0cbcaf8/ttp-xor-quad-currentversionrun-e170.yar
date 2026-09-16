rule TTP_XOR_QUAD_CurrentVersionRun_e170 {
  strings:
    $key_e170 = { b2 1f [2] 96 11 [2] bd 3d [2] 93 1f [2] 87 04 [2] 88 1e [2] 96 03 [2] 94 02 [2] 8f 04 [2] 93 03 [2] 8f 2c }

  condition:
    any of them
}
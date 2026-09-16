rule TTP_XOR_QUAD_CurrentVersionRun_e171 {
  strings:
    $key_e171 = { b2 1e [2] 96 10 [2] bd 3c [2] 93 1e [2] 87 05 [2] 88 1f [2] 96 02 [2] 94 03 [2] 8f 05 [2] 93 02 [2] 8f 2d }

  condition:
    any of them
}
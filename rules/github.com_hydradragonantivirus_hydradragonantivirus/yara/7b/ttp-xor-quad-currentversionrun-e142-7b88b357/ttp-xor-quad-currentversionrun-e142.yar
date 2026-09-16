rule TTP_XOR_QUAD_CurrentVersionRun_e142 {
  strings:
    $key_e142 = { b2 2d [2] 96 23 [2] bd 0f [2] 93 2d [2] 87 36 [2] 88 2c [2] 96 31 [2] 94 30 [2] 8f 36 [2] 93 31 [2] 8f 1e }

  condition:
    any of them
}
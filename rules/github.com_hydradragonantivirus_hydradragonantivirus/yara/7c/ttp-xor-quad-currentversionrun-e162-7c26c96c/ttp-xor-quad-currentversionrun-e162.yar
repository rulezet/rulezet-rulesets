rule TTP_XOR_QUAD_CurrentVersionRun_e162 {
  strings:
    $key_e162 = { b2 0d [2] 96 03 [2] bd 2f [2] 93 0d [2] 87 16 [2] 88 0c [2] 96 11 [2] 94 10 [2] 8f 16 [2] 93 11 [2] 8f 3e }

  condition:
    any of them
}
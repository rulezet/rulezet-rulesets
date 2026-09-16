rule TTP_XOR_QUAD_CurrentVersionRun_e150 {
  strings:
    $key_e150 = { b2 3f [2] 96 31 [2] bd 1d [2] 93 3f [2] 87 24 [2] 88 3e [2] 96 23 [2] 94 22 [2] 8f 24 [2] 93 23 [2] 8f 0c }

  condition:
    any of them
}
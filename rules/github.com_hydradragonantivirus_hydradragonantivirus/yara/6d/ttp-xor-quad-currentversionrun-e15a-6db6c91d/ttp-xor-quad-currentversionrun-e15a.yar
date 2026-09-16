rule TTP_XOR_QUAD_CurrentVersionRun_e15a {
  strings:
    $key_e15a = { b2 35 [2] 96 3b [2] bd 17 [2] 93 35 [2] 87 2e [2] 88 34 [2] 96 29 [2] 94 28 [2] 8f 2e [2] 93 29 [2] 8f 06 }

  condition:
    any of them
}
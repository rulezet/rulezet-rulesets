rule TTP_XOR_QUAD_CurrentVersionRun_e15d {
  strings:
    $key_e15d = { b2 32 [2] 96 3c [2] bd 10 [2] 93 32 [2] 87 29 [2] 88 33 [2] 96 2e [2] 94 2f [2] 8f 29 [2] 93 2e [2] 8f 01 }

  condition:
    any of them
}
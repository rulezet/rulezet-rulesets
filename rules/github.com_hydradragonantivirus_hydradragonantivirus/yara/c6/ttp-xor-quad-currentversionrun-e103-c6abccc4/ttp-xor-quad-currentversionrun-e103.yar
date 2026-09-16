rule TTP_XOR_QUAD_CurrentVersionRun_e103 {
  strings:
    $key_e103 = { b2 6c [2] 96 62 [2] bd 4e [2] 93 6c [2] 87 77 [2] 88 6d [2] 96 70 [2] 94 71 [2] 8f 77 [2] 93 70 [2] 8f 5f }

  condition:
    any of them
}
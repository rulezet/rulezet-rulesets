rule TTP_XOR_QUAD_CurrentVersionRun_e113 {
  strings:
    $key_e113 = { b2 7c [2] 96 72 [2] bd 5e [2] 93 7c [2] 87 67 [2] 88 7d [2] 96 60 [2] 94 61 [2] 8f 67 [2] 93 60 [2] 8f 4f }

  condition:
    any of them
}
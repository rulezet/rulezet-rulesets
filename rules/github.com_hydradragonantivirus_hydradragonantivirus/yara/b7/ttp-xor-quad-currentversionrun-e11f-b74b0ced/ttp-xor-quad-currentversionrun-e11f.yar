rule TTP_XOR_QUAD_CurrentVersionRun_e11f {
  strings:
    $key_e11f = { b2 70 [2] 96 7e [2] bd 52 [2] 93 70 [2] 87 6b [2] 88 71 [2] 96 6c [2] 94 6d [2] 8f 6b [2] 93 6c [2] 8f 43 }

  condition:
    any of them
}
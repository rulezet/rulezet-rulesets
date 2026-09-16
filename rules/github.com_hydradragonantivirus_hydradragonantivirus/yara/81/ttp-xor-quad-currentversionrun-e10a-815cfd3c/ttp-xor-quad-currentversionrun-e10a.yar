rule TTP_XOR_QUAD_CurrentVersionRun_e10a {
  strings:
    $key_e10a = { b2 65 [2] 96 6b [2] bd 47 [2] 93 65 [2] 87 7e [2] 88 64 [2] 96 79 [2] 94 78 [2] 8f 7e [2] 93 79 [2] 8f 56 }

  condition:
    any of them
}
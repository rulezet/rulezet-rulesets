rule TTP_XOR_QUAD_CurrentVersionRun_e12d {
  strings:
    $key_e12d = { b2 42 [2] 96 4c [2] bd 60 [2] 93 42 [2] 87 59 [2] 88 43 [2] 96 5e [2] 94 5f [2] 8f 59 [2] 93 5e [2] 8f 71 }

  condition:
    any of them
}
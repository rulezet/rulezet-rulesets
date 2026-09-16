rule TTP_XOR_QUAD_CurrentVersionRun_e10d {
  strings:
    $key_e10d = { b2 62 [2] 96 6c [2] bd 40 [2] 93 62 [2] 87 79 [2] 88 63 [2] 96 7e [2] 94 7f [2] 8f 79 [2] 93 7e [2] 8f 51 }

  condition:
    any of them
}
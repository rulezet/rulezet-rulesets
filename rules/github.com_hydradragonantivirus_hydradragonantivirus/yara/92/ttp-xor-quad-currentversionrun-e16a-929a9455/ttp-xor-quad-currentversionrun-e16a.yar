rule TTP_XOR_QUAD_CurrentVersionRun_e16a {
  strings:
    $key_e16a = { b2 05 [2] 96 0b [2] bd 27 [2] 93 05 [2] 87 1e [2] 88 04 [2] 96 19 [2] 94 18 [2] 8f 1e [2] 93 19 [2] 8f 36 }

  condition:
    any of them
}
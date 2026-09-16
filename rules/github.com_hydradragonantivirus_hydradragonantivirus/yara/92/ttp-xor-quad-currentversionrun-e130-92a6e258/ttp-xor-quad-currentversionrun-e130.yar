rule TTP_XOR_QUAD_CurrentVersionRun_e130 {
  strings:
    $key_e130 = { b2 5f [2] 96 51 [2] bd 7d [2] 93 5f [2] 87 44 [2] 88 5e [2] 96 43 [2] 94 42 [2] 8f 44 [2] 93 43 [2] 8f 6c }

  condition:
    any of them
}
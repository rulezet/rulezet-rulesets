rule TTP_XOR_QUAD_CurrentVersionRun_e111 {
  strings:
    $key_e111 = { b2 7e [2] 96 70 [2] bd 5c [2] 93 7e [2] 87 65 [2] 88 7f [2] 96 62 [2] 94 63 [2] 8f 65 [2] 93 62 [2] 8f 4d }

  condition:
    any of them
}
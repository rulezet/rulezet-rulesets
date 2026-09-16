rule TTP_XOR_QUAD_CurrentVersionRun_e13d {
  strings:
    $key_e13d = { b2 52 [2] 96 5c [2] bd 70 [2] 93 52 [2] 87 49 [2] 88 53 [2] 96 4e [2] 94 4f [2] 8f 49 [2] 93 4e [2] 8f 61 }

  condition:
    any of them
}
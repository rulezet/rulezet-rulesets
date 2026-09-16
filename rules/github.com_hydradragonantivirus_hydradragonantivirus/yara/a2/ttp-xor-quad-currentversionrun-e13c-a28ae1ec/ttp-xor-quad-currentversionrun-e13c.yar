rule TTP_XOR_QUAD_CurrentVersionRun_e13c {
  strings:
    $key_e13c = { b2 53 [2] 96 5d [2] bd 71 [2] 93 53 [2] 87 48 [2] 88 52 [2] 96 4f [2] 94 4e [2] 8f 48 [2] 93 4f [2] 8f 60 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_e11e {
  strings:
    $key_e11e = { b2 71 [2] 96 7f [2] bd 53 [2] 93 71 [2] 87 6a [2] 88 70 [2] 96 6d [2] 94 6c [2] 8f 6a [2] 93 6d [2] 8f 42 }

  condition:
    any of them
}
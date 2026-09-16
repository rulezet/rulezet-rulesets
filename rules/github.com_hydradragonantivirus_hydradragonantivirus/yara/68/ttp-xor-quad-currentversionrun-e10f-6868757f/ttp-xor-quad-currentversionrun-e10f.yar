rule TTP_XOR_QUAD_CurrentVersionRun_e10f {
  strings:
    $key_e10f = { b2 60 [2] 96 6e [2] bd 42 [2] 93 60 [2] 87 7b [2] 88 61 [2] 96 7c [2] 94 7d [2] 8f 7b [2] 93 7c [2] 8f 53 }

  condition:
    any of them
}
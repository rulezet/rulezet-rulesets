rule TTP_XOR_QUAD_CurrentVersionRun_e13f {
  strings:
    $key_e13f = { b2 50 [2] 96 5e [2] bd 72 [2] 93 50 [2] 87 4b [2] 88 51 [2] 96 4c [2] 94 4d [2] 8f 4b [2] 93 4c [2] 8f 63 }

  condition:
    any of them
}
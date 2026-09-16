rule TTP_XOR_QUAD_CurrentVersionRun_cf3e {
  strings:
    $key_cf3e = { 9c 51 [2] b8 5f [2] 93 73 [2] bd 51 [2] a9 4a [2] a6 50 [2] b8 4d [2] ba 4c [2] a1 4a [2] bd 4d [2] a1 62 }

  condition:
    any of them
}
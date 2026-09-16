rule TTP_XOR_QUAD_CurrentVersionRun_cf3c {
  strings:
    $key_cf3c = { 9c 53 [2] b8 5d [2] 93 71 [2] bd 53 [2] a9 48 [2] a6 52 [2] b8 4f [2] ba 4e [2] a1 48 [2] bd 4f [2] a1 60 }

  condition:
    any of them
}
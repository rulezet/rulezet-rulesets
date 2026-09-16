rule TTP_XOR_QUAD_CurrentVersionRun_cf3d {
  strings:
    $key_cf3d = { 9c 52 [2] b8 5c [2] 93 70 [2] bd 52 [2] a9 49 [2] a6 53 [2] b8 4e [2] ba 4f [2] a1 49 [2] bd 4e [2] a1 61 }

  condition:
    any of them
}
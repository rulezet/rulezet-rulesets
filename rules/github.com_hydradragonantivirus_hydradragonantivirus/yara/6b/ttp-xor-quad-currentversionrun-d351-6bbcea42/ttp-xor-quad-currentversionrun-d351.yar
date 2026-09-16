rule TTP_XOR_QUAD_CurrentVersionRun_d351 {
  strings:
    $key_d351 = { 80 3e [2] a4 30 [2] 8f 1c [2] a1 3e [2] b5 25 [2] ba 3f [2] a4 22 [2] a6 23 [2] bd 25 [2] a1 22 [2] bd 0d }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_ca41 {
  strings:
    $key_ca41 = { 99 2e [2] bd 20 [2] 96 0c [2] b8 2e [2] ac 35 [2] a3 2f [2] bd 32 [2] bf 33 [2] a4 35 [2] b8 32 [2] a4 1d }

  condition:
    any of them
}
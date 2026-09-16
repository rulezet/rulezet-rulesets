rule TTP_XOR_QUAD_CurrentVersionRun_ca31 {
  strings:
    $key_ca31 = { 99 5e [2] bd 50 [2] 96 7c [2] b8 5e [2] ac 45 [2] a3 5f [2] bd 42 [2] bf 43 [2] a4 45 [2] b8 42 [2] a4 6d }

  condition:
    any of them
}
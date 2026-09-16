rule TTP_XOR_QUAD_CurrentVersionRun_ca21 {
  strings:
    $key_ca21 = { 99 4e [2] bd 40 [2] 96 6c [2] b8 4e [2] ac 55 [2] a3 4f [2] bd 52 [2] bf 53 [2] a4 55 [2] b8 52 [2] a4 7d }

  condition:
    any of them
}
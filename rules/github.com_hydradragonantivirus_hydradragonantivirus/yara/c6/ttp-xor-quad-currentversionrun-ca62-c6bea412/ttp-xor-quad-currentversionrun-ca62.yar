rule TTP_XOR_QUAD_CurrentVersionRun_ca62 {
  strings:
    $key_ca62 = { 99 0d [2] bd 03 [2] 96 2f [2] b8 0d [2] ac 16 [2] a3 0c [2] bd 11 [2] bf 10 [2] a4 16 [2] b8 11 [2] a4 3e }

  condition:
    any of them
}
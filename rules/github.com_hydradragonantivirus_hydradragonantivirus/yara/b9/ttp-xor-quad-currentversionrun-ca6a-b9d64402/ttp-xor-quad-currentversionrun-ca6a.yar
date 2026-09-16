rule TTP_XOR_QUAD_CurrentVersionRun_ca6a {
  strings:
    $key_ca6a = { 99 05 [2] bd 0b [2] 96 27 [2] b8 05 [2] ac 1e [2] a3 04 [2] bd 19 [2] bf 18 [2] a4 1e [2] b8 19 [2] a4 36 }

  condition:
    any of them
}
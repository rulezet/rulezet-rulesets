rule TTP_XOR_QUAD_CurrentVersionRun_ca3a {
  strings:
    $key_ca3a = { 99 55 [2] bd 5b [2] 96 77 [2] b8 55 [2] ac 4e [2] a3 54 [2] bd 49 [2] bf 48 [2] a4 4e [2] b8 49 [2] a4 66 }

  condition:
    any of them
}
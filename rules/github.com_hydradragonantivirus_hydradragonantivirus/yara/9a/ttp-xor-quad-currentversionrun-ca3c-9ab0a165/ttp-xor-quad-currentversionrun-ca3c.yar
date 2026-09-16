rule TTP_XOR_QUAD_CurrentVersionRun_ca3c {
  strings:
    $key_ca3c = { 99 53 [2] bd 5d [2] 96 71 [2] b8 53 [2] ac 48 [2] a3 52 [2] bd 4f [2] bf 4e [2] a4 48 [2] b8 4f [2] a4 60 }

  condition:
    any of them
}
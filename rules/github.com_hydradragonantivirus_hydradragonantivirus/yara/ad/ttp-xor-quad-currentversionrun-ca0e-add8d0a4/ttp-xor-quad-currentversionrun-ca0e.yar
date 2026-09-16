rule TTP_XOR_QUAD_CurrentVersionRun_ca0e {
  strings:
    $key_ca0e = { 99 61 [2] bd 6f [2] 96 43 [2] b8 61 [2] ac 7a [2] a3 60 [2] bd 7d [2] bf 7c [2] a4 7a [2] b8 7d [2] a4 52 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_ca7e {
  strings:
    $key_ca7e = { 99 11 [2] bd 1f [2] 96 33 [2] b8 11 [2] ac 0a [2] a3 10 [2] bd 0d [2] bf 0c [2] a4 0a [2] b8 0d [2] a4 22 }

  condition:
    any of them
}
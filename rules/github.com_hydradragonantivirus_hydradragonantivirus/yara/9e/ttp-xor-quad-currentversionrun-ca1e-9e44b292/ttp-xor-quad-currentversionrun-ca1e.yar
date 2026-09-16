rule TTP_XOR_QUAD_CurrentVersionRun_ca1e {
  strings:
    $key_ca1e = { 99 71 [2] bd 7f [2] 96 53 [2] b8 71 [2] ac 6a [2] a3 70 [2] bd 6d [2] bf 6c [2] a4 6a [2] b8 6d [2] a4 42 }

  condition:
    any of them
}
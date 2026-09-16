rule TTP_XOR_QUAD_CurrentVersionRun_ca3e {
  strings:
    $key_ca3e = { 99 51 [2] bd 5f [2] 96 73 [2] b8 51 [2] ac 4a [2] a3 50 [2] bd 4d [2] bf 4c [2] a4 4a [2] b8 4d [2] a4 62 }

  condition:
    any of them
}
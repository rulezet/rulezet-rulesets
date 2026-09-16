rule TTP_XOR_QUAD_CurrentVersionRun_ca12 {
  strings:
    $key_ca12 = { 99 7d [2] bd 73 [2] 96 5f [2] b8 7d [2] ac 66 [2] a3 7c [2] bd 61 [2] bf 60 [2] a4 66 [2] b8 61 [2] a4 4e }

  condition:
    any of them
}
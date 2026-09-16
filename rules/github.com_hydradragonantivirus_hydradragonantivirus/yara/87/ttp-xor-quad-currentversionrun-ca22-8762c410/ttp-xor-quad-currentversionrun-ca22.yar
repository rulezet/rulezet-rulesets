rule TTP_XOR_QUAD_CurrentVersionRun_ca22 {
  strings:
    $key_ca22 = { 99 4d [2] bd 43 [2] 96 6f [2] b8 4d [2] ac 56 [2] a3 4c [2] bd 51 [2] bf 50 [2] a4 56 [2] b8 51 [2] a4 7e }

  condition:
    any of them
}
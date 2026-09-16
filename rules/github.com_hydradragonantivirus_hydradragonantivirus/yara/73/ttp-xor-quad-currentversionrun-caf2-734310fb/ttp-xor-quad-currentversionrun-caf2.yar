rule TTP_XOR_QUAD_CurrentVersionRun_caf2 {
  strings:
    $key_caf2 = { 99 9d [2] bd 93 [2] 96 bf [2] b8 9d [2] ac 86 [2] a3 9c [2] bd 81 [2] bf 80 [2] a4 86 [2] b8 81 [2] a4 ae }

  condition:
    any of them
}
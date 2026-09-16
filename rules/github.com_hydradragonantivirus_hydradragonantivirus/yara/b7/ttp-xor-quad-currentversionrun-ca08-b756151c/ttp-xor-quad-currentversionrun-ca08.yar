rule TTP_XOR_QUAD_CurrentVersionRun_ca08 {
  strings:
    $key_ca08 = { 99 67 [2] bd 69 [2] 96 45 [2] b8 67 [2] ac 7c [2] a3 66 [2] bd 7b [2] bf 7a [2] a4 7c [2] b8 7b [2] a4 54 }

  condition:
    any of them
}
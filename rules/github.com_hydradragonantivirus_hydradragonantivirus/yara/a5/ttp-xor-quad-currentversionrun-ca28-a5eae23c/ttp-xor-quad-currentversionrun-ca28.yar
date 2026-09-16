rule TTP_XOR_QUAD_CurrentVersionRun_ca28 {
  strings:
    $key_ca28 = { 99 47 [2] bd 49 [2] 96 65 [2] b8 47 [2] ac 5c [2] a3 46 [2] bd 5b [2] bf 5a [2] a4 5c [2] b8 5b [2] a4 74 }

  condition:
    any of them
}
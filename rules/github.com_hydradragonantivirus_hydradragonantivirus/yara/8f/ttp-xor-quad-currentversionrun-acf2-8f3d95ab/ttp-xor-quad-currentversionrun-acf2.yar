rule TTP_XOR_QUAD_CurrentVersionRun_acf2 {
  strings:
    $key_acf2 = { ff 9d [2] db 93 [2] f0 bf [2] de 9d [2] ca 86 [2] c5 9c [2] db 81 [2] d9 80 [2] c2 86 [2] de 81 [2] c2 ae }

  condition:
    any of them
}
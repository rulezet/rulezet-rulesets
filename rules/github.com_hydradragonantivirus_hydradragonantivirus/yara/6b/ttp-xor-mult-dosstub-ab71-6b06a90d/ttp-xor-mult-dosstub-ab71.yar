rule TTP_XOR_MULT_DOSStub_ab71 {
  strings:
    $key_ab71 = { ff 19 [2] 8b 01 [2] cc 03 [2] 8b 12 [2] c5 1e [2] c9 14 [2] de 1f [2] c5 51 [2] f8 }

  condition:
    any of them
}
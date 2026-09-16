rule TTP_XOR_MULT_DOSStub_e579 {
  strings:
    $key_e579 = { b1 11 [2] c5 09 [2] 82 0b [2] c5 1a [2] 8b 16 [2] 87 1c [2] 90 17 [2] 8b 59 [2] b6 }

  condition:
    any of them
}
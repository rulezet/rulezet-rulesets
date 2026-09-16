rule TTP_XOR_MULT_DOSStub_c979 {
  strings:
    $key_c979 = { 9d 11 [2] e9 09 [2] ae 0b [2] e9 1a [2] a7 16 [2] ab 1c [2] bc 17 [2] a7 59 [2] 9a }

  condition:
    any of them
}
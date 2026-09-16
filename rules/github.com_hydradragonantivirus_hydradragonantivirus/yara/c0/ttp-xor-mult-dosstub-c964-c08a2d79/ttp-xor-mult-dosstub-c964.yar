rule TTP_XOR_MULT_DOSStub_c964 {
  strings:
    $key_c964 = { 9d 0c [2] e9 14 [2] ae 16 [2] e9 07 [2] a7 0b [2] ab 01 [2] bc 0a [2] a7 44 [2] 9a }

  condition:
    any of them
}
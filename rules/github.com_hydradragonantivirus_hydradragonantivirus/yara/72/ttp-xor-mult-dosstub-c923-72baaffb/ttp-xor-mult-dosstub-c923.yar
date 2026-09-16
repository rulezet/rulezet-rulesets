rule TTP_XOR_MULT_DOSStub_c923 {
  strings:
    $key_c923 = { 9d 4b [2] e9 53 [2] ae 51 [2] e9 40 [2] a7 4c [2] ab 46 [2] bc 4d [2] a7 03 [2] 9a }

  condition:
    any of them
}
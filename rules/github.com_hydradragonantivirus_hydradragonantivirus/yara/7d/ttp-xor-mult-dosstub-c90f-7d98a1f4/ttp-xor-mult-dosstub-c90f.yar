rule TTP_XOR_MULT_DOSStub_c90f {
  strings:
    $key_c90f = { 9d 67 [2] e9 7f [2] ae 7d [2] e9 6c [2] a7 60 [2] ab 6a [2] bc 61 [2] a7 2f [2] 9a }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_c96a {
  strings:
    $key_c96a = { 9d 02 [2] e9 1a [2] ae 18 [2] e9 09 [2] a7 05 [2] ab 0f [2] bc 04 [2] a7 4a [2] 9a }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_c92f {
  strings:
    $key_c92f = { 9d 47 [2] e9 5f [2] ae 5d [2] e9 4c [2] a7 40 [2] ab 4a [2] bc 41 [2] a7 0f [2] 9a }

  condition:
    any of them
}
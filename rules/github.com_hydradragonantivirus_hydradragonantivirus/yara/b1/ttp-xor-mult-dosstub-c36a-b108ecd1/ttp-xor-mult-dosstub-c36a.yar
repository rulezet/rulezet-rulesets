rule TTP_XOR_MULT_DOSStub_c36a {
  strings:
    $key_c36a = { 97 02 [2] e3 1a [2] a4 18 [2] e3 09 [2] ad 05 [2] a1 0f [2] b6 04 [2] ad 4a [2] 90 }

  condition:
    any of them
}
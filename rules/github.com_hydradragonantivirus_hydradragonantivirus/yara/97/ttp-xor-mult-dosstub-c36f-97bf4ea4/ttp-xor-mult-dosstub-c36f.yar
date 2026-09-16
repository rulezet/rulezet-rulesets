rule TTP_XOR_MULT_DOSStub_c36f {
  strings:
    $key_c36f = { 97 07 [2] e3 1f [2] a4 1d [2] e3 0c [2] ad 00 [2] a1 0a [2] b6 01 [2] ad 4f [2] 90 }

  condition:
    any of them
}
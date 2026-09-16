rule TTP_XOR_MULT_DOSStub_c56f {
  strings:
    $key_c56f = { 91 07 [2] e5 1f [2] a2 1d [2] e5 0c [2] ab 00 [2] a7 0a [2] b0 01 [2] ab 4f [2] 96 }

  condition:
    any of them
}
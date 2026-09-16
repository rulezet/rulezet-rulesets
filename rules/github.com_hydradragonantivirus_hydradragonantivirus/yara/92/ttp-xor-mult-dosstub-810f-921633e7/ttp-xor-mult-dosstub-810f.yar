rule TTP_XOR_MULT_DOSStub_810f {
  strings:
    $key_810f = { d5 67 [2] a1 7f [2] e6 7d [2] a1 6c [2] ef 60 [2] e3 6a [2] f4 61 [2] ef 2f [2] d2 }

  condition:
    any of them
}
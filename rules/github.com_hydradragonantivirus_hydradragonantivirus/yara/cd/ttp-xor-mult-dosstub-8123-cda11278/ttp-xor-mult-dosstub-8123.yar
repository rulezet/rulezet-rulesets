rule TTP_XOR_MULT_DOSStub_8123 {
  strings:
    $key_8123 = { d5 4b [2] a1 53 [2] e6 51 [2] a1 40 [2] ef 4c [2] e3 46 [2] f4 4d [2] ef 03 [2] d2 }

  condition:
    any of them
}
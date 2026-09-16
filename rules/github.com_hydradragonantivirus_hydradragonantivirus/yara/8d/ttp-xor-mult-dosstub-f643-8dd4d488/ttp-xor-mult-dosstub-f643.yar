rule TTP_XOR_MULT_DOSStub_f643 {
  strings:
    $key_f643 = { a2 2b [2] d6 33 [2] 91 31 [2] d6 20 [2] 98 2c [2] 94 26 [2] 83 2d [2] 98 63 [2] a5 }

  condition:
    any of them
}
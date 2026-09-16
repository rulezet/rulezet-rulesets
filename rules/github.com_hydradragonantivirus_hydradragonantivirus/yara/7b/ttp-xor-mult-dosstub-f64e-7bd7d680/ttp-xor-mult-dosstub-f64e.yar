rule TTP_XOR_MULT_DOSStub_f64e {
  strings:
    $key_f64e = { a2 26 [2] d6 3e [2] 91 3c [2] d6 2d [2] 98 21 [2] 94 2b [2] 83 20 [2] 98 6e [2] a5 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f65f {
  strings:
    $key_f65f = { a2 37 [2] d6 2f [2] 91 2d [2] d6 3c [2] 98 30 [2] 94 3a [2] 83 31 [2] 98 7f [2] a5 }

  condition:
    any of them
}
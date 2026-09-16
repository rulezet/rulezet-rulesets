rule TTP_XOR_MULT_DOSStub_f622 {
  strings:
    $key_f622 = { a2 4a [2] d6 52 [2] 91 50 [2] d6 41 [2] 98 4d [2] 94 47 [2] 83 4c [2] 98 02 [2] a5 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_b122 {
  strings:
    $key_b122 = { e5 4a [2] 91 52 [2] d6 50 [2] 91 41 [2] df 4d [2] d3 47 [2] c4 4c [2] df 02 [2] e2 }

  condition:
    any of them
}
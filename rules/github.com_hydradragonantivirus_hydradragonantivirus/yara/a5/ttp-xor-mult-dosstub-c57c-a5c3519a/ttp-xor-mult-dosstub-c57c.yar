rule TTP_XOR_MULT_DOSStub_c57c {
  strings:
    $key_c57c = { 91 14 [2] e5 0c [2] a2 0e [2] e5 1f [2] ab 13 [2] a7 19 [2] b0 12 [2] ab 5c [2] 96 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_c54c {
  strings:
    $key_c54c = { 91 24 [2] e5 3c [2] a2 3e [2] e5 2f [2] ab 23 [2] a7 29 [2] b0 22 [2] ab 6c [2] 96 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_4f3c {
  strings:
    $key_4f3c = { 1b 54 [2] 6f 4c [2] 28 4e [2] 6f 5f [2] 21 53 [2] 2d 59 [2] 3a 52 [2] 21 1c [2] 1c }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_6f1c {
  strings:
    $key_6f1c = { 3b 74 [2] 4f 6c [2] 08 6e [2] 4f 7f [2] 01 73 [2] 0d 79 [2] 1a 72 [2] 01 3c [2] 3c }

  condition:
    any of them
}
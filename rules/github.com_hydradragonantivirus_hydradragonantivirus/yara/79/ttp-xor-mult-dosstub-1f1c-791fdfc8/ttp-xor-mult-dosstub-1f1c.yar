rule TTP_XOR_MULT_DOSStub_1f1c {
  strings:
    $key_1f1c = { 4b 74 [2] 3f 6c [2] 78 6e [2] 3f 7f [2] 71 73 [2] 7d 79 [2] 6a 72 [2] 71 3c [2] 4c }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_fde2 {
  strings:
    $key_fde2 = { a9 8a [2] dd 92 [2] 9a 90 [2] dd 81 [2] 93 8d [2] 9f 87 [2] 88 8c [2] 93 c2 [2] ae }

  condition:
    any of them
}
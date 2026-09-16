rule TTP_XOR_MULT_DOSStub_fd77 {
  strings:
    $key_fd77 = { a9 1f [2] dd 07 [2] 9a 05 [2] dd 14 [2] 93 18 [2] 9f 12 [2] 88 19 [2] 93 57 [2] ae }

  condition:
    any of them
}
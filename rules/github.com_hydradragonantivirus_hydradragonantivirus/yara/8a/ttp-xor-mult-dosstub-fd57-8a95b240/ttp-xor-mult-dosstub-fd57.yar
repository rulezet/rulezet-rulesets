rule TTP_XOR_MULT_DOSStub_fd57 {
  strings:
    $key_fd57 = { a9 3f [2] dd 27 [2] 9a 25 [2] dd 34 [2] 93 38 [2] 9f 32 [2] 88 39 [2] 93 77 [2] ae }

  condition:
    any of them
}
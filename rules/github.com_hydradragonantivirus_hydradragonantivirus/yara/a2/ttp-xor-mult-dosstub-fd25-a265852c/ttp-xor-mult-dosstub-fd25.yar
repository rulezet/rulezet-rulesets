rule TTP_XOR_MULT_DOSStub_fd25 {
  strings:
    $key_fd25 = { a9 4d [2] dd 55 [2] 9a 57 [2] dd 46 [2] 93 4a [2] 9f 40 [2] 88 4b [2] 93 05 [2] ae }

  condition:
    any of them
}
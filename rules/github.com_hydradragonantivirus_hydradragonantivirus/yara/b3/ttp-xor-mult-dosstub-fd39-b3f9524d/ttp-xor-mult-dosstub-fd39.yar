rule TTP_XOR_MULT_DOSStub_fd39 {
  strings:
    $key_fd39 = { a9 51 [2] dd 49 [2] 9a 4b [2] dd 5a [2] 93 56 [2] 9f 5c [2] 88 57 [2] 93 19 [2] ae }

  condition:
    any of them
}
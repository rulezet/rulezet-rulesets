rule TTP_XOR_MULT_DOSStub_fd28 {
  strings:
    $key_fd28 = { a9 40 [2] dd 58 [2] 9a 5a [2] dd 4b [2] 93 47 [2] 9f 4d [2] 88 46 [2] 93 08 [2] ae }

  condition:
    any of them
}
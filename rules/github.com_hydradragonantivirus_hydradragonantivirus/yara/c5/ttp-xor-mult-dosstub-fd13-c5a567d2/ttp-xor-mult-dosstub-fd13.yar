rule TTP_XOR_MULT_DOSStub_fd13 {
  strings:
    $key_fd13 = { a9 7b [2] dd 63 [2] 9a 61 [2] dd 70 [2] 93 7c [2] 9f 76 [2] 88 7d [2] 93 33 [2] ae }

  condition:
    any of them
}
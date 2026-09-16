rule TTP_XOR_MULT_DOSStub_fd64 {
  strings:
    $key_fd64 = { a9 0c [2] dd 14 [2] 9a 16 [2] dd 07 [2] 93 0b [2] 9f 01 [2] 88 0a [2] 93 44 [2] ae }

  condition:
    any of them
}
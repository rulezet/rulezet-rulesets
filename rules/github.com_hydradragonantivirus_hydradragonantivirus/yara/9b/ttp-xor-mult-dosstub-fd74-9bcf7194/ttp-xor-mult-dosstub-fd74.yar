rule TTP_XOR_MULT_DOSStub_fd74 {
  strings:
    $key_fd74 = { a9 1c [2] dd 04 [2] 9a 06 [2] dd 17 [2] 93 1b [2] 9f 11 [2] 88 1a [2] 93 54 [2] ae }

  condition:
    any of them
}
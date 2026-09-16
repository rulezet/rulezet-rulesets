rule TTP_XOR_MULT_DOSStub_fdeb {
  strings:
    $key_fdeb = { a9 83 [2] dd 9b [2] 9a 99 [2] dd 88 [2] 93 84 [2] 9f 8e [2] 88 85 [2] 93 cb [2] ae }

  condition:
    any of them
}
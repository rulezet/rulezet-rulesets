rule TTP_XOR_MULT_DOSStub_fdfe {
  strings:
    $key_fdfe = { a9 96 [2] dd 8e [2] 9a 8c [2] dd 9d [2] 93 91 [2] 9f 9b [2] 88 90 [2] 93 de [2] ae }

  condition:
    any of them
}
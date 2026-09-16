rule TTP_XOR_MULT_DOSStub_fdfa {
  strings:
    $key_fdfa = { a9 92 [2] dd 8a [2] 9a 88 [2] dd 99 [2] 93 95 [2] 9f 9f [2] 88 94 [2] 93 da [2] ae }

  condition:
    any of them
}
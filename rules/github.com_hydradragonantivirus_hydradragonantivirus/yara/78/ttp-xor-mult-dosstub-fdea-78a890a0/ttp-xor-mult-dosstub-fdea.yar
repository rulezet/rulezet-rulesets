rule TTP_XOR_MULT_DOSStub_fdea {
  strings:
    $key_fdea = { a9 82 [2] dd 9a [2] 9a 98 [2] dd 89 [2] 93 85 [2] 9f 8f [2] 88 84 [2] 93 ca [2] ae }

  condition:
    any of them
}
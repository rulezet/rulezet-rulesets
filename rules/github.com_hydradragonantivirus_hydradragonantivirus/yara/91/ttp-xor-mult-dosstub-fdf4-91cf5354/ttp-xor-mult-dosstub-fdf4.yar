rule TTP_XOR_MULT_DOSStub_fdf4 {
  strings:
    $key_fdf4 = { a9 9c [2] dd 84 [2] 9a 86 [2] dd 97 [2] 93 9b [2] 9f 91 [2] 88 9a [2] 93 d4 [2] ae }

  condition:
    any of them
}
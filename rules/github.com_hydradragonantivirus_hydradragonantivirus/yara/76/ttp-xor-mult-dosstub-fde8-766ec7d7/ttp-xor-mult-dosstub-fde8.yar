rule TTP_XOR_MULT_DOSStub_fde8 {
  strings:
    $key_fde8 = { a9 80 [2] dd 98 [2] 9a 9a [2] dd 8b [2] 93 87 [2] 9f 8d [2] 88 86 [2] 93 c8 [2] ae }

  condition:
    any of them
}
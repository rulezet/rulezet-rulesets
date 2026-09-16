rule TTP_XOR_MULT_DOSStub_fded {
  strings:
    $key_fded = { a9 85 [2] dd 9d [2] 9a 9f [2] dd 8e [2] 93 82 [2] 9f 88 [2] 88 83 [2] 93 cd [2] ae }

  condition:
    any of them
}
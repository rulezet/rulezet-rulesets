rule TTP_XOR_MULT_DOSStub_291c {
  strings:
    $key_291c = { 7d 74 [2] 09 6c [2] 4e 6e [2] 09 7f [2] 47 73 [2] 4b 79 [2] 5c 72 [2] 47 3c [2] 7a }

  condition:
    any of them
}
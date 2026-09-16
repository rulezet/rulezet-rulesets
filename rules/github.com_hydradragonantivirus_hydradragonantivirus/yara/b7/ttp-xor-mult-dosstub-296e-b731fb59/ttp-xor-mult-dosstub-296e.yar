rule TTP_XOR_MULT_DOSStub_296e {
  strings:
    $key_296e = { 7d 06 [2] 09 1e [2] 4e 1c [2] 09 0d [2] 47 01 [2] 4b 0b [2] 5c 00 [2] 47 4e [2] 7a }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_291e {
  strings:
    $key_291e = { 7d 76 [2] 09 6e [2] 4e 6c [2] 09 7d [2] 47 71 [2] 4b 7b [2] 5c 70 [2] 47 3e [2] 7a }

  condition:
    any of them
}
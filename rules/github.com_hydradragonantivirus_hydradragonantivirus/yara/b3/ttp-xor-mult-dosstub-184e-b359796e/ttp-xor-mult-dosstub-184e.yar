rule TTP_XOR_MULT_DOSStub_184e {
  strings:
    $key_184e = { 4c 26 [2] 38 3e [2] 7f 3c [2] 38 2d [2] 76 21 [2] 7a 2b [2] 6d 20 [2] 76 6e [2] 4b }

  condition:
    any of them
}
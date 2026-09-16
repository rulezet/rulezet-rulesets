rule TTP_XOR_MULT_DOSStub_332c {
  strings:
    $key_332c = { 67 44 [2] 13 5c [2] 54 5e [2] 13 4f [2] 5d 43 [2] 51 49 [2] 46 42 [2] 5d 0c [2] 60 }

  condition:
    any of them
}
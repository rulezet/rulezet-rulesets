rule TTP_XOR_MULT_DOSStub_2a3c {
  strings:
    $key_2a3c = { 7e 54 [2] 0a 4c [2] 4d 4e [2] 0a 5f [2] 44 53 [2] 48 59 [2] 5f 52 [2] 44 1c [2] 79 }

  condition:
    any of them
}
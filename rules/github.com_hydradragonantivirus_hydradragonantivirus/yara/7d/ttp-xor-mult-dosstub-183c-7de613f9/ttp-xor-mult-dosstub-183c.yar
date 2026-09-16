rule TTP_XOR_MULT_DOSStub_183c {
  strings:
    $key_183c = { 4c 54 [2] 38 4c [2] 7f 4e [2] 38 5f [2] 76 53 [2] 7a 59 [2] 6d 52 [2] 76 1c [2] 4b }

  condition:
    any of them
}
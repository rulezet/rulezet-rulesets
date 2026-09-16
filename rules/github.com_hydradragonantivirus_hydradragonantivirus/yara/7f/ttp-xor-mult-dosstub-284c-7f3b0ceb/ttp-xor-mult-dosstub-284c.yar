rule TTP_XOR_MULT_DOSStub_284c {
  strings:
    $key_284c = { 7c 24 [2] 08 3c [2] 4f 3e [2] 08 2f [2] 46 23 [2] 4a 29 [2] 5d 22 [2] 46 6c [2] 7b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_213c {
  strings:
    $key_213c = { 75 54 [2] 01 4c [2] 46 4e [2] 01 5f [2] 4f 53 [2] 43 59 [2] 54 52 [2] 4f 1c [2] 72 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_503c {
  strings:
    $key_503c = { 04 54 [2] 70 4c [2] 37 4e [2] 70 5f [2] 3e 53 [2] 32 59 [2] 25 52 [2] 3e 1c [2] 03 }

  condition:
    any of them
}
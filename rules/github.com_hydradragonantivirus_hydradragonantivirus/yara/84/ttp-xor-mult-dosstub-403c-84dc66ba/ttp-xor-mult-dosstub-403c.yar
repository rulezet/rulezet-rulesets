rule TTP_XOR_MULT_DOSStub_403c {
  strings:
    $key_403c = { 14 54 [2] 60 4c [2] 27 4e [2] 60 5f [2] 2e 53 [2] 22 59 [2] 35 52 [2] 2e 1c [2] 13 }

  condition:
    any of them
}
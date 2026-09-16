rule TTP_XOR_MULT_DOSStub_713c {
  strings:
    $key_713c = { 25 54 [2] 51 4c [2] 16 4e [2] 51 5f [2] 1f 53 [2] 13 59 [2] 04 52 [2] 1f 1c [2] 22 }

  condition:
    any of them
}
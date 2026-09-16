rule TTP_XOR_MULT_DOSStub_363c {
  strings:
    $key_363c = { 62 54 [2] 16 4c [2] 51 4e [2] 16 5f [2] 58 53 [2] 54 59 [2] 43 52 [2] 58 1c [2] 65 }

  condition:
    any of them
}
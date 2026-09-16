rule TTP_XOR_MULT_DOSStub_063c {
  strings:
    $key_063c = { 52 54 [2] 26 4c [2] 61 4e [2] 26 5f [2] 68 53 [2] 64 59 [2] 73 52 [2] 68 1c [2] 55 }

  condition:
    any of them
}
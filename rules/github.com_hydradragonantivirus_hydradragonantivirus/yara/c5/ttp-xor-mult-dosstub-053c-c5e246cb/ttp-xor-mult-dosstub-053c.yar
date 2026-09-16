rule TTP_XOR_MULT_DOSStub_053c {
  strings:
    $key_053c = { 51 54 [2] 25 4c [2] 62 4e [2] 25 5f [2] 6b 53 [2] 67 59 [2] 70 52 [2] 6b 1c [2] 56 }

  condition:
    any of them
}
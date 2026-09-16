rule TTP_XOR_MULT_DOSStub_7d3c {
  strings:
    $key_7d3c = { 29 54 [2] 5d 4c [2] 1a 4e [2] 5d 5f [2] 13 53 [2] 1f 59 [2] 08 52 [2] 13 1c [2] 2e }

  condition:
    any of them
}
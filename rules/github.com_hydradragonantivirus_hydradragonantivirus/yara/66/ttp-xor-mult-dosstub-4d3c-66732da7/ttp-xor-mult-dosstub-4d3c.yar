rule TTP_XOR_MULT_DOSStub_4d3c {
  strings:
    $key_4d3c = { 19 54 [2] 6d 4c [2] 2a 4e [2] 6d 5f [2] 23 53 [2] 2f 59 [2] 38 52 [2] 23 1c [2] 1e }

  condition:
    any of them
}
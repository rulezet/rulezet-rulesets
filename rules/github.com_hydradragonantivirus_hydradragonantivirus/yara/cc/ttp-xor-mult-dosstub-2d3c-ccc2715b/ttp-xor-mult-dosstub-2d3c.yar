rule TTP_XOR_MULT_DOSStub_2d3c {
  strings:
    $key_2d3c = { 79 54 [2] 0d 4c [2] 4a 4e [2] 0d 5f [2] 43 53 [2] 4f 59 [2] 58 52 [2] 43 1c [2] 7e }

  condition:
    any of them
}
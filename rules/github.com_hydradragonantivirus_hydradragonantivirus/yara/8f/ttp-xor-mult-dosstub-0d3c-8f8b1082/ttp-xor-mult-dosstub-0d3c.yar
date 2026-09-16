rule TTP_XOR_MULT_DOSStub_0d3c {
  strings:
    $key_0d3c = { 59 54 [2] 2d 4c [2] 6a 4e [2] 2d 5f [2] 63 53 [2] 6f 59 [2] 78 52 [2] 63 1c [2] 5e }

  condition:
    any of them
}
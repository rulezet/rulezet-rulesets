rule TTP_XOR_MULT_DOSStub_6d3c {
  strings:
    $key_6d3c = { 39 54 [2] 4d 4c [2] 0a 4e [2] 4d 5f [2] 03 53 [2] 0f 59 [2] 18 52 [2] 03 1c [2] 3e }

  condition:
    any of them
}
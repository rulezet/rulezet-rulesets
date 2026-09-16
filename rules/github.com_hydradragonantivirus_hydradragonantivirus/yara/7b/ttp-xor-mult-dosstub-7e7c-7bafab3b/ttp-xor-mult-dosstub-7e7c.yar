rule TTP_XOR_MULT_DOSStub_7e7c {
  strings:
    $key_7e7c = { 2a 14 [2] 5e 0c [2] 19 0e [2] 5e 1f [2] 10 13 [2] 1c 19 [2] 0b 12 [2] 10 5c [2] 2d }

  condition:
    any of them
}
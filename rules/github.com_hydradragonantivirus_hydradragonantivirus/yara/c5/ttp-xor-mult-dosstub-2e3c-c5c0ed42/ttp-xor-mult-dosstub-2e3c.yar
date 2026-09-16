rule TTP_XOR_MULT_DOSStub_2e3c {
  strings:
    $key_2e3c = { 7a 54 [2] 0e 4c [2] 49 4e [2] 0e 5f [2] 40 53 [2] 4c 59 [2] 5b 52 [2] 40 1c [2] 7d }

  condition:
    any of them
}
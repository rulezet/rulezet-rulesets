rule TTP_XOR_MULT_DOSStub_49ed {
  strings:
    $key_49ed = { 1d 85 [2] 69 9d [2] 2e 9f [2] 69 8e [2] 27 82 [2] 2b 88 [2] 3c 83 [2] 27 cd [2] 1a }

  condition:
    any of them
}
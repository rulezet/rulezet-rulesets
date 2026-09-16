rule TTP_XOR_MULT_DOSStub_24ed {
  strings:
    $key_24ed = { 70 85 [2] 04 9d [2] 43 9f [2] 04 8e [2] 4a 82 [2] 46 88 [2] 51 83 [2] 4a cd [2] 77 }

  condition:
    any of them
}
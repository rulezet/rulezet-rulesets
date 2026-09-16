rule TTP_XOR_MULT_DOSStub_42ed {
  strings:
    $key_42ed = { 16 85 [2] 62 9d [2] 25 9f [2] 62 8e [2] 2c 82 [2] 20 88 [2] 37 83 [2] 2c cd [2] 11 }

  condition:
    any of them
}
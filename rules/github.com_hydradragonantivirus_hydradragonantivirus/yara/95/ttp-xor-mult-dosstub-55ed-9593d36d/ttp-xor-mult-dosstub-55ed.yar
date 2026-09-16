rule TTP_XOR_MULT_DOSStub_55ed {
  strings:
    $key_55ed = { 01 85 [2] 75 9d [2] 32 9f [2] 75 8e [2] 3b 82 [2] 37 88 [2] 20 83 [2] 3b cd [2] 06 }

  condition:
    any of them
}
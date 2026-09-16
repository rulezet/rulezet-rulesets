rule TTP_XOR_MULT_DOSStub_77ed {
  strings:
    $key_77ed = { 23 85 [2] 57 9d [2] 10 9f [2] 57 8e [2] 19 82 [2] 15 88 [2] 02 83 [2] 19 cd [2] 24 }

  condition:
    any of them
}
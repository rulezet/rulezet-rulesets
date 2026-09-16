rule TTP_XOR_MULT_DOSStub_46ed {
  strings:
    $key_46ed = { 12 85 [2] 66 9d [2] 21 9f [2] 66 8e [2] 28 82 [2] 24 88 [2] 33 83 [2] 28 cd [2] 15 }

  condition:
    any of them
}
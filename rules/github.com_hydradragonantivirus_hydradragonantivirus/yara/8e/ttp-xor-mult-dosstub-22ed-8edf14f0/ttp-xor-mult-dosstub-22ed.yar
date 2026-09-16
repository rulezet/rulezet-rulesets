rule TTP_XOR_MULT_DOSStub_22ed {
  strings:
    $key_22ed = { 76 85 [2] 02 9d [2] 45 9f [2] 02 8e [2] 4c 82 [2] 40 88 [2] 57 83 [2] 4c cd [2] 71 }

  condition:
    any of them
}
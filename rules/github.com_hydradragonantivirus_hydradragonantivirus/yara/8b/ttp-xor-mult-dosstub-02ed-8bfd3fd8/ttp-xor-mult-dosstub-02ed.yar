rule TTP_XOR_MULT_DOSStub_02ed {
  strings:
    $key_02ed = { 56 85 [2] 22 9d [2] 65 9f [2] 22 8e [2] 6c 82 [2] 60 88 [2] 77 83 [2] 6c cd [2] 51 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_32ed {
  strings:
    $key_32ed = { 66 85 [2] 12 9d [2] 55 9f [2] 12 8e [2] 5c 82 [2] 50 88 [2] 47 83 [2] 5c cd [2] 61 }

  condition:
    any of them
}
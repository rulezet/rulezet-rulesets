rule TTP_XOR_MULT_DOSStub_f2ed {
  strings:
    $key_f2ed = { a6 85 [2] d2 9d [2] 95 9f [2] d2 8e [2] 9c 82 [2] 90 88 [2] 87 83 [2] 9c cd [2] a1 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_e2ed {
  strings:
    $key_e2ed = { b6 85 [2] c2 9d [2] 85 9f [2] c2 8e [2] 8c 82 [2] 80 88 [2] 97 83 [2] 8c cd [2] b1 }

  condition:
    any of them
}
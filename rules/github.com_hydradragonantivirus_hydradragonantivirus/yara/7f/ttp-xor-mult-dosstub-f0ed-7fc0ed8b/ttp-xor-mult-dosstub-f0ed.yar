rule TTP_XOR_MULT_DOSStub_f0ed {
  strings:
    $key_f0ed = { a4 85 [2] d0 9d [2] 97 9f [2] d0 8e [2] 9e 82 [2] 92 88 [2] 85 83 [2] 9e cd [2] a3 }

  condition:
    any of them
}
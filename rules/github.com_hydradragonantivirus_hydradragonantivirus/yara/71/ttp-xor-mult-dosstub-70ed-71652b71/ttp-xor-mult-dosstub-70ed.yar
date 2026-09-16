rule TTP_XOR_MULT_DOSStub_70ed {
  strings:
    $key_70ed = { 24 85 [2] 50 9d [2] 17 9f [2] 50 8e [2] 1e 82 [2] 12 88 [2] 05 83 [2] 1e cd [2] 23 }

  condition:
    any of them
}
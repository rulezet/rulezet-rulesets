rule TTP_XOR_MULT_DOSStub_30ed {
  strings:
    $key_30ed = { 64 85 [2] 10 9d [2] 57 9f [2] 10 8e [2] 5e 82 [2] 52 88 [2] 45 83 [2] 5e cd [2] 63 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_40ed {
  strings:
    $key_40ed = { 14 85 [2] 60 9d [2] 27 9f [2] 60 8e [2] 2e 82 [2] 22 88 [2] 35 83 [2] 2e cd [2] 13 }

  condition:
    any of them
}
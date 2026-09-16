rule TTP_XOR_MULT_DOSStub_60ed {
  strings:
    $key_60ed = { 34 85 [2] 40 9d [2] 07 9f [2] 40 8e [2] 0e 82 [2] 02 88 [2] 15 83 [2] 0e cd [2] 33 }

  condition:
    any of them
}
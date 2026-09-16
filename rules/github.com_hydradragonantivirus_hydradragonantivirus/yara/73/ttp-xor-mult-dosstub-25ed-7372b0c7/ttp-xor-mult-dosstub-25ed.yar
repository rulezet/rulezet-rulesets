rule TTP_XOR_MULT_DOSStub_25ed {
  strings:
    $key_25ed = { 71 85 [2] 05 9d [2] 42 9f [2] 05 8e [2] 4b 82 [2] 47 88 [2] 50 83 [2] 4b cd [2] 76 }

  condition:
    any of them
}
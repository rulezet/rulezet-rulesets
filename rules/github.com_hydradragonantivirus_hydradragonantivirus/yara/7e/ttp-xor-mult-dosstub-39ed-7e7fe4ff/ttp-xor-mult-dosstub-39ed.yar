rule TTP_XOR_MULT_DOSStub_39ed {
  strings:
    $key_39ed = { 6d 85 [2] 19 9d [2] 5e 9f [2] 19 8e [2] 57 82 [2] 5b 88 [2] 4c 83 [2] 57 cd [2] 6a }

  condition:
    any of them
}
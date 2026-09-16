rule TTP_XOR_MULT_DOSStub_78ed {
  strings:
    $key_78ed = { 2c 85 [2] 58 9d [2] 1f 9f [2] 58 8e [2] 16 82 [2] 1a 88 [2] 0d 83 [2] 16 cd [2] 2b }

  condition:
    any of them
}
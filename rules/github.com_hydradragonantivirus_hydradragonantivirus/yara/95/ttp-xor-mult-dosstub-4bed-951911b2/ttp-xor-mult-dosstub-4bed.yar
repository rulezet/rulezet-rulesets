rule TTP_XOR_MULT_DOSStub_4bed {
  strings:
    $key_4bed = { 1f 85 [2] 6b 9d [2] 2c 9f [2] 6b 8e [2] 25 82 [2] 29 88 [2] 3e 83 [2] 25 cd [2] 18 }

  condition:
    any of them
}
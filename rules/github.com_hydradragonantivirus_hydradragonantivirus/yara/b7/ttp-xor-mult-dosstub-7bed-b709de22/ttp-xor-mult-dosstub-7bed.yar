rule TTP_XOR_MULT_DOSStub_7bed {
  strings:
    $key_7bed = { 2f 85 [2] 5b 9d [2] 1c 9f [2] 5b 8e [2] 15 82 [2] 19 88 [2] 0e 83 [2] 15 cd [2] 28 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_1bed {
  strings:
    $key_1bed = { 4f 85 [2] 3b 9d [2] 7c 9f [2] 3b 8e [2] 75 82 [2] 79 88 [2] 6e 83 [2] 75 cd [2] 48 }

  condition:
    any of them
}
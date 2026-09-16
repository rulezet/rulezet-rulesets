rule TTP_XOR_MULT_DOSStub_5bed {
  strings:
    $key_5bed = { 0f 85 [2] 7b 9d [2] 3c 9f [2] 7b 8e [2] 35 82 [2] 39 88 [2] 2e 83 [2] 35 cd [2] 08 }

  condition:
    any of them
}
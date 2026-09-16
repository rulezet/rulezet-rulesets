rule TTP_XOR_MULT_DOSStub_4ded {
  strings:
    $key_4ded = { 19 85 [2] 6d 9d [2] 2a 9f [2] 6d 8e [2] 23 82 [2] 2f 88 [2] 38 83 [2] 23 cd [2] 1e }

  condition:
    any of them
}
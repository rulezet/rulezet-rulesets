rule TTP_XOR_MULT_DOSStub_7ded {
  strings:
    $key_7ded = { 29 85 [2] 5d 9d [2] 1a 9f [2] 5d 8e [2] 13 82 [2] 1f 88 [2] 08 83 [2] 13 cd [2] 2e }

  condition:
    any of them
}
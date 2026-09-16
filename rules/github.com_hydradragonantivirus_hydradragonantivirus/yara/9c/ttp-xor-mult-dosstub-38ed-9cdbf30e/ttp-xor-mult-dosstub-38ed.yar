rule TTP_XOR_MULT_DOSStub_38ed {
  strings:
    $key_38ed = { 6c 85 [2] 18 9d [2] 5f 9f [2] 18 8e [2] 56 82 [2] 5a 88 [2] 4d 83 [2] 56 cd [2] 6b }

  condition:
    any of them
}
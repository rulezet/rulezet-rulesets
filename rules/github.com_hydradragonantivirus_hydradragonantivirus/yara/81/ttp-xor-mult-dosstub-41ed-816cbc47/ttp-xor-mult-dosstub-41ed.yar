rule TTP_XOR_MULT_DOSStub_41ed {
  strings:
    $key_41ed = { 15 85 [2] 61 9d [2] 26 9f [2] 61 8e [2] 2f 82 [2] 23 88 [2] 34 83 [2] 2f cd [2] 12 }

  condition:
    any of them
}
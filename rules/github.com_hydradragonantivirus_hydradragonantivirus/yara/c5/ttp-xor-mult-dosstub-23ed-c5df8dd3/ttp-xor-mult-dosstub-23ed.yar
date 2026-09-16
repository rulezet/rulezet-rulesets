rule TTP_XOR_MULT_DOSStub_23ed {
  strings:
    $key_23ed = { 77 85 [2] 03 9d [2] 44 9f [2] 03 8e [2] 4d 82 [2] 41 88 [2] 56 83 [2] 4d cd [2] 70 }

  condition:
    any of them
}
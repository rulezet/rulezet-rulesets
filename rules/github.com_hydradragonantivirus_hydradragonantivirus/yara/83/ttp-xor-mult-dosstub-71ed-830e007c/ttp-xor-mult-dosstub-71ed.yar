rule TTP_XOR_MULT_DOSStub_71ed {
  strings:
    $key_71ed = { 25 85 [2] 51 9d [2] 16 9f [2] 51 8e [2] 1f 82 [2] 13 88 [2] 04 83 [2] 1f cd [2] 22 }

  condition:
    any of them
}
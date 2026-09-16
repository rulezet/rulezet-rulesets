rule TTP_XOR_MULT_DOSStub_11ed {
  strings:
    $key_11ed = { 45 85 [2] 31 9d [2] 76 9f [2] 31 8e [2] 7f 82 [2] 73 88 [2] 64 83 [2] 7f cd [2] 42 }

  condition:
    any of them
}
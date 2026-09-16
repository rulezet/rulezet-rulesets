rule TTP_XOR_MULT_DOSStub_16ed {
  strings:
    $key_16ed = { 42 85 [2] 36 9d [2] 71 9f [2] 36 8e [2] 78 82 [2] 74 88 [2] 63 83 [2] 78 cd [2] 45 }

  condition:
    any of them
}
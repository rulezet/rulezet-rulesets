rule TTP_XOR_MULT_DOSStub_2b5b {
  strings:
    $key_2b5b = { 7f 33 [2] 0b 2b [2] 4c 29 [2] 0b 38 [2] 45 34 [2] 49 3e [2] 5e 35 [2] 45 7b [2] 78 }

  condition:
    any of them
}
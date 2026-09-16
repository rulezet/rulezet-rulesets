rule TTP_XOR_MULT_DOSStub_5ef8 {
  strings:
    $key_5ef8 = { 0a 90 [2] 7e 88 [2] 39 8a [2] 7e 9b [2] 30 97 [2] 3c 9d [2] 2b 96 [2] 30 d8 [2] 0d }

  condition:
    any of them
}
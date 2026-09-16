rule TTP_XOR_MULT_DOSStub_3ef8 {
  strings:
    $key_3ef8 = { 6a 90 [2] 1e 88 [2] 59 8a [2] 1e 9b [2] 50 97 [2] 5c 9d [2] 4b 96 [2] 50 d8 [2] 6d }

  condition:
    any of them
}
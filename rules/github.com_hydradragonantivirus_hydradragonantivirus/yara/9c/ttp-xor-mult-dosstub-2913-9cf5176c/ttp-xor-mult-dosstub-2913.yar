rule TTP_XOR_MULT_DOSStub_2913 {
  strings:
    $key_2913 = { 7d 7b [2] 09 63 [2] 4e 61 [2] 09 70 [2] 47 7c [2] 4b 76 [2] 5c 7d [2] 47 33 [2] 7a }

  condition:
    any of them
}
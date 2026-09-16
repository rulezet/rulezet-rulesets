rule TTP_XOR_MULT_DOSStub_6bf8 {
  strings:
    $key_6bf8 = { 3f 90 [2] 4b 88 [2] 0c 8a [2] 4b 9b [2] 05 97 [2] 09 9d [2] 1e 96 [2] 05 d8 [2] 38 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_6af8 {
  strings:
    $key_6af8 = { 3e 90 [2] 4a 88 [2] 0d 8a [2] 4a 9b [2] 04 97 [2] 08 9d [2] 1f 96 [2] 04 d8 [2] 39 }

  condition:
    any of them
}
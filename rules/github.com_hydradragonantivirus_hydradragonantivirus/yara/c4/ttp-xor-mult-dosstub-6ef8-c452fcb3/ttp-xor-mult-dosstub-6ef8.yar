rule TTP_XOR_MULT_DOSStub_6ef8 {
  strings:
    $key_6ef8 = { 3a 90 [2] 4e 88 [2] 09 8a [2] 4e 9b [2] 00 97 [2] 0c 9d [2] 1b 96 [2] 00 d8 [2] 3d }

  condition:
    any of them
}
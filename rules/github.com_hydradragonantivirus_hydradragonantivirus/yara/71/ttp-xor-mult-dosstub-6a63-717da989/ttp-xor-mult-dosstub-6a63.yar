rule TTP_XOR_MULT_DOSStub_6a63 {
  strings:
    $key_6a63 = { 3e 0b [2] 4a 13 [2] 0d 11 [2] 4a 00 [2] 04 0c [2] 08 06 [2] 1f 0d [2] 04 43 [2] 39 }

  condition:
    any of them
}
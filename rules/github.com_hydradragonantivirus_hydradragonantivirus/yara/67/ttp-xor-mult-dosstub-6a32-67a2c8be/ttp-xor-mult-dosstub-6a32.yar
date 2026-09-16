rule TTP_XOR_MULT_DOSStub_6a32 {
  strings:
    $key_6a32 = { 3e 5a [2] 4a 42 [2] 0d 40 [2] 4a 51 [2] 04 5d [2] 08 57 [2] 1f 5c [2] 04 12 [2] 39 }

  condition:
    any of them
}
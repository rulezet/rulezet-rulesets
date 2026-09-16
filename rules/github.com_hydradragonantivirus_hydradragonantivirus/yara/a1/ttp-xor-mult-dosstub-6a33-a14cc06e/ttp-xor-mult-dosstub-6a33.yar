rule TTP_XOR_MULT_DOSStub_6a33 {
  strings:
    $key_6a33 = { 3e 5b [2] 4a 43 [2] 0d 41 [2] 4a 50 [2] 04 5c [2] 08 56 [2] 1f 5d [2] 04 13 [2] 39 }

  condition:
    any of them
}
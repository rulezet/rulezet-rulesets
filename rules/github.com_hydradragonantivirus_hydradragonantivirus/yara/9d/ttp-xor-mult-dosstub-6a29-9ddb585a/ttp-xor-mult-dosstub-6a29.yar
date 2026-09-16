rule TTP_XOR_MULT_DOSStub_6a29 {
  strings:
    $key_6a29 = { 3e 41 [2] 4a 59 [2] 0d 5b [2] 4a 4a [2] 04 46 [2] 08 4c [2] 1f 47 [2] 04 09 [2] 39 }

  condition:
    any of them
}
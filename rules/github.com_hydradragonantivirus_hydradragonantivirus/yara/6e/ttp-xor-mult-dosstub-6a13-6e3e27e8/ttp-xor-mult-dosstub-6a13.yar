rule TTP_XOR_MULT_DOSStub_6a13 {
  strings:
    $key_6a13 = { 3e 7b [2] 4a 63 [2] 0d 61 [2] 4a 70 [2] 04 7c [2] 08 76 [2] 1f 7d [2] 04 33 [2] 39 }

  condition:
    any of them
}
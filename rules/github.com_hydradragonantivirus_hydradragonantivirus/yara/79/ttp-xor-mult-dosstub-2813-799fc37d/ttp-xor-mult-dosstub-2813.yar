rule TTP_XOR_MULT_DOSStub_2813 {
  strings:
    $key_2813 = { 7c 7b [2] 08 63 [2] 4f 61 [2] 08 70 [2] 46 7c [2] 4a 76 [2] 5d 7d [2] 46 33 [2] 7b }

  condition:
    any of them
}
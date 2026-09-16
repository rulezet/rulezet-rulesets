rule TTP_XOR_MULT_DOSStub_2829 {
  strings:
    $key_2829 = { 7c 41 [2] 08 59 [2] 4f 5b [2] 08 4a [2] 46 46 [2] 4a 4c [2] 5d 47 [2] 46 09 [2] 7b }

  condition:
    any of them
}
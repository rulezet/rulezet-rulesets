rule TTP_XOR_MULT_DOSStub_7b29 {
  strings:
    $key_7b29 = { 2f 41 [2] 5b 59 [2] 1c 5b [2] 5b 4a [2] 15 46 [2] 19 4c [2] 0e 47 [2] 15 09 [2] 28 }

  condition:
    any of them
}
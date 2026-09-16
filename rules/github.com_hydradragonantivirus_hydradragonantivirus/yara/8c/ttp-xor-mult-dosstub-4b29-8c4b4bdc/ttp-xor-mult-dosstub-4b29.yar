rule TTP_XOR_MULT_DOSStub_4b29 {
  strings:
    $key_4b29 = { 1f 41 [2] 6b 59 [2] 2c 5b [2] 6b 4a [2] 25 46 [2] 29 4c [2] 3e 47 [2] 25 09 [2] 18 }

  condition:
    any of them
}
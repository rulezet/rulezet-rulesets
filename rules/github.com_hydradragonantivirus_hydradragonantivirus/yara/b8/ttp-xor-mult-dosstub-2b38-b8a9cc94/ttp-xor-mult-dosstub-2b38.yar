rule TTP_XOR_MULT_DOSStub_2b38 {
  strings:
    $key_2b38 = { 7f 50 [2] 0b 48 [2] 4c 4a [2] 0b 5b [2] 45 57 [2] 49 5d [2] 5e 56 [2] 45 18 [2] 78 }

  condition:
    any of them
}
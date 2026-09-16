rule TTP_XOR_MULT_DOSStub_2b14 {
  strings:
    $key_2b14 = { 7f 7c [2] 0b 64 [2] 4c 66 [2] 0b 77 [2] 45 7b [2] 49 71 [2] 5e 7a [2] 45 34 [2] 78 }

  condition:
    any of them
}
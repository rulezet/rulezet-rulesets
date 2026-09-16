rule TTP_XOR_MULT_DOSStub_2b05 {
  strings:
    $key_2b05 = { 7f 6d [2] 0b 75 [2] 4c 77 [2] 0b 66 [2] 45 6a [2] 49 60 [2] 5e 6b [2] 45 25 [2] 78 }

  condition:
    any of them
}
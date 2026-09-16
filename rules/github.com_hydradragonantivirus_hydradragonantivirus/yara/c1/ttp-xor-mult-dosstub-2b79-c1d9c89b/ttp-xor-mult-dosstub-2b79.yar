rule TTP_XOR_MULT_DOSStub_2b79 {
  strings:
    $key_2b79 = { 7f 11 [2] 0b 09 [2] 4c 0b [2] 0b 1a [2] 45 16 [2] 49 1c [2] 5e 17 [2] 45 59 [2] 78 }

  condition:
    any of them
}
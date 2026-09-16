rule TTP_XOR_MULT_DOSStub_2b62 {
  strings:
    $key_2b62 = { 7f 0a [2] 0b 12 [2] 4c 10 [2] 0b 01 [2] 45 0d [2] 49 07 [2] 5e 0c [2] 45 42 [2] 78 }

  condition:
    any of them
}
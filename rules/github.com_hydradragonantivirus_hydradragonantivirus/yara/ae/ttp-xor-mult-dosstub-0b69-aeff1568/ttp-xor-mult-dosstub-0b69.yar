rule TTP_XOR_MULT_DOSStub_0b69 {
  strings:
    $key_0b69 = { 5f 01 [2] 2b 19 [2] 6c 1b [2] 2b 0a [2] 65 06 [2] 69 0c [2] 7e 07 [2] 65 49 [2] 58 }

  condition:
    any of them
}
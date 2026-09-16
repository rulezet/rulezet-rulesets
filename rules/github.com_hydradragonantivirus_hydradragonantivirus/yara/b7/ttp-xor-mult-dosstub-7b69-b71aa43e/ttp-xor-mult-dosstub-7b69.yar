rule TTP_XOR_MULT_DOSStub_7b69 {
  strings:
    $key_7b69 = { 2f 01 [2] 5b 19 [2] 1c 1b [2] 5b 0a [2] 15 06 [2] 19 0c [2] 0e 07 [2] 15 49 [2] 28 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_7209 {
  strings:
    $key_7209 = { 26 61 [2] 52 79 [2] 15 7b [2] 52 6a [2] 1c 66 [2] 10 6c [2] 07 67 [2] 1c 29 [2] 21 }

  condition:
    any of them
}
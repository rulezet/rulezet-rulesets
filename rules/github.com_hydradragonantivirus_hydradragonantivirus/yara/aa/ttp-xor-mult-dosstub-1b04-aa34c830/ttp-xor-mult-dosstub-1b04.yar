rule TTP_XOR_MULT_DOSStub_1b04 {
  strings:
    $key_1b04 = { 4f 6c [2] 3b 74 [2] 7c 76 [2] 3b 67 [2] 75 6b [2] 79 61 [2] 6e 6a [2] 75 24 [2] 48 }

  condition:
    any of them
}
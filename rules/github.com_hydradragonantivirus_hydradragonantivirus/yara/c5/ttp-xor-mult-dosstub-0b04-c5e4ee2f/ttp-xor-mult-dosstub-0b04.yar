rule TTP_XOR_MULT_DOSStub_0b04 {
  strings:
    $key_0b04 = { 5f 6c [2] 2b 74 [2] 6c 76 [2] 2b 67 [2] 65 6b [2] 69 61 [2] 7e 6a [2] 65 24 [2] 58 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_4b04 {
  strings:
    $key_4b04 = { 1f 6c [2] 6b 74 [2] 2c 76 [2] 6b 67 [2] 25 6b [2] 29 61 [2] 3e 6a [2] 25 24 [2] 18 }

  condition:
    any of them
}
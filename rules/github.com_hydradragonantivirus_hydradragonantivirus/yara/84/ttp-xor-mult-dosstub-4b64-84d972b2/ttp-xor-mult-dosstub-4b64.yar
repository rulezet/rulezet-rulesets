rule TTP_XOR_MULT_DOSStub_4b64 {
  strings:
    $key_4b64 = { 1f 0c [2] 6b 14 [2] 2c 16 [2] 6b 07 [2] 25 0b [2] 29 01 [2] 3e 0a [2] 25 44 [2] 18 }

  condition:
    any of them
}
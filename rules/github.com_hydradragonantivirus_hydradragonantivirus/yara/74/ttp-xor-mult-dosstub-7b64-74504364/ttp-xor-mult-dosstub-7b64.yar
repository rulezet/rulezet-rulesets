rule TTP_XOR_MULT_DOSStub_7b64 {
  strings:
    $key_7b64 = { 2f 0c [2] 5b 14 [2] 1c 16 [2] 5b 07 [2] 15 0b [2] 19 01 [2] 0e 0a [2] 15 44 [2] 28 }

  condition:
    any of them
}
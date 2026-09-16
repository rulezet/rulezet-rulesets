rule TTP_XOR_MULT_DOSStub_5b64 {
  strings:
    $key_5b64 = { 0f 0c [2] 7b 14 [2] 3c 16 [2] 7b 07 [2] 35 0b [2] 39 01 [2] 2e 0a [2] 35 44 [2] 08 }

  condition:
    any of them
}
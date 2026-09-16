rule TTP_XOR_MULT_DOSStub_1b64 {
  strings:
    $key_1b64 = { 4f 0c [2] 3b 14 [2] 7c 16 [2] 3b 07 [2] 75 0b [2] 79 01 [2] 6e 0a [2] 75 44 [2] 48 }

  condition:
    any of them
}
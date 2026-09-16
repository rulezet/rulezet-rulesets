rule TTP_XOR_MULT_DOSStub_5c09 {
  strings:
    $key_5c09 = { 08 61 [2] 7c 79 [2] 3b 7b [2] 7c 6a [2] 32 66 [2] 3e 6c [2] 29 67 [2] 32 29 [2] 0f }

  condition:
    any of them
}
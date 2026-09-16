rule TTP_XOR_MULT_DOSStub_3c09 {
  strings:
    $key_3c09 = { 68 61 [2] 1c 79 [2] 5b 7b [2] 1c 6a [2] 52 66 [2] 5e 6c [2] 49 67 [2] 52 29 [2] 6f }

  condition:
    any of them
}
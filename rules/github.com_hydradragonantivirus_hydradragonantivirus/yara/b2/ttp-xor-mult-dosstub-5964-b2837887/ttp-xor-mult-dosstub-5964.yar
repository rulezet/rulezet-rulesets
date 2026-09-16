rule TTP_XOR_MULT_DOSStub_5964 {
  strings:
    $key_5964 = { 0d 0c [2] 79 14 [2] 3e 16 [2] 79 07 [2] 37 0b [2] 3b 01 [2] 2c 0a [2] 37 44 [2] 0a }

  condition:
    any of them
}
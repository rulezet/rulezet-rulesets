rule TTP_XOR_MULT_DOSStub_7e64 {
  strings:
    $key_7e64 = { 2a 0c [2] 5e 14 [2] 19 16 [2] 5e 07 [2] 10 0b [2] 1c 01 [2] 0b 0a [2] 10 44 [2] 2d }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_7ee8 {
  strings:
    $key_7ee8 = { 2a 80 [2] 5e 98 [2] 19 9a [2] 5e 8b [2] 10 87 [2] 1c 8d [2] 0b 86 [2] 10 c8 [2] 2d }

  condition:
    any of them
}
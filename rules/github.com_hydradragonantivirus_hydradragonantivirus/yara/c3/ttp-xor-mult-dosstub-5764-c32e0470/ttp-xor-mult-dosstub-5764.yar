rule TTP_XOR_MULT_DOSStub_5764 {
  strings:
    $key_5764 = { 03 0c [2] 77 14 [2] 30 16 [2] 77 07 [2] 39 0b [2] 35 01 [2] 22 0a [2] 39 44 [2] 04 }

  condition:
    any of them
}
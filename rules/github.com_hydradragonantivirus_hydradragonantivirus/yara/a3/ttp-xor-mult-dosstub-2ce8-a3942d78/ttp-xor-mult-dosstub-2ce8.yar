rule TTP_XOR_MULT_DOSStub_2ce8 {
  strings:
    $key_2ce8 = { 78 80 [2] 0c 98 [2] 4b 9a [2] 0c 8b [2] 42 87 [2] 4e 8d [2] 59 86 [2] 42 c8 [2] 7f }

  condition:
    any of them
}
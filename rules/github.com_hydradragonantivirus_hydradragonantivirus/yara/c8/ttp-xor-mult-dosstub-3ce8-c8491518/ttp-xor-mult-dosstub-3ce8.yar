rule TTP_XOR_MULT_DOSStub_3ce8 {
  strings:
    $key_3ce8 = { 68 80 [2] 1c 98 [2] 5b 9a [2] 1c 8b [2] 52 87 [2] 5e 8d [2] 49 86 [2] 52 c8 [2] 6f }

  condition:
    any of them
}
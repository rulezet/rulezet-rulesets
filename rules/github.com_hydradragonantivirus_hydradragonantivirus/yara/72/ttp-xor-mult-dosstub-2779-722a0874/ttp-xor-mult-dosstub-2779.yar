rule TTP_XOR_MULT_DOSStub_2779 {
  strings:
    $key_2779 = { 73 11 [2] 07 09 [2] 40 0b [2] 07 1a [2] 49 16 [2] 45 1c [2] 52 17 [2] 49 59 [2] 74 }

  condition:
    any of them
}
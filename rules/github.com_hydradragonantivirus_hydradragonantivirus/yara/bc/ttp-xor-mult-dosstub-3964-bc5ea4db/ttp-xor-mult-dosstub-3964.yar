rule TTP_XOR_MULT_DOSStub_3964 {
  strings:
    $key_3964 = { 6d 0c [2] 19 14 [2] 5e 16 [2] 19 07 [2] 57 0b [2] 5b 01 [2] 4c 0a [2] 57 44 [2] 6a }

  condition:
    any of them
}
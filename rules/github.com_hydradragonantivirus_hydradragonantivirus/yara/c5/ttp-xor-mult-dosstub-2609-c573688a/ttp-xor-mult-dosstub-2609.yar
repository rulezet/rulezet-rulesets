rule TTP_XOR_MULT_DOSStub_2609 {
  strings:
    $key_2609 = { 72 61 [2] 06 79 [2] 41 7b [2] 06 6a [2] 48 66 [2] 44 6c [2] 53 67 [2] 48 29 [2] 75 }

  condition:
    any of them
}
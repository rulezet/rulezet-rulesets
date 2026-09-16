rule TTP_XOR_MULT_DOSStub_0769 {
  strings:
    $key_0769 = { 53 01 [2] 27 19 [2] 60 1b [2] 27 0a [2] 69 06 [2] 65 0c [2] 72 07 [2] 69 49 [2] 54 }

  condition:
    any of them
}
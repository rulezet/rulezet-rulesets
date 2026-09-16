rule TTP_XOR_MULT_DOSStub_0724 {
  strings:
    $key_0724 = { 53 4c [2] 27 54 [2] 60 56 [2] 27 47 [2] 69 4b [2] 65 41 [2] 72 4a [2] 69 04 [2] 54 }

  condition:
    any of them
}
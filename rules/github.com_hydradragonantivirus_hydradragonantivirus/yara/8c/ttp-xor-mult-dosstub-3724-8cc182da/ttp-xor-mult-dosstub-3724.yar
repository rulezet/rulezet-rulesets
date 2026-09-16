rule TTP_XOR_MULT_DOSStub_3724 {
  strings:
    $key_3724 = { 63 4c [2] 17 54 [2] 50 56 [2] 17 47 [2] 59 4b [2] 55 41 [2] 42 4a [2] 59 04 [2] 64 }

  condition:
    any of them
}
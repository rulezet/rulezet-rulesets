rule TTP_XOR_MULT_DOSStub_7d24 {
  strings:
    $key_7d24 = { 29 4c [2] 5d 54 [2] 1a 56 [2] 5d 47 [2] 13 4b [2] 1f 41 [2] 08 4a [2] 13 04 [2] 2e }

  condition:
    any of them
}
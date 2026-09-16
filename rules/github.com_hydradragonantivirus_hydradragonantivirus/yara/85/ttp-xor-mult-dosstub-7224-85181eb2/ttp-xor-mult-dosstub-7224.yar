rule TTP_XOR_MULT_DOSStub_7224 {
  strings:
    $key_7224 = { 26 4c [2] 52 54 [2] 15 56 [2] 52 47 [2] 1c 4b [2] 10 41 [2] 07 4a [2] 1c 04 [2] 21 }

  condition:
    any of them
}
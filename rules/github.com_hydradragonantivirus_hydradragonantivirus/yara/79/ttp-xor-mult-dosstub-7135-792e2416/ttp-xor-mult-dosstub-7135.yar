rule TTP_XOR_MULT_DOSStub_7135 {
  strings:
    $key_7135 = { 25 5d [2] 51 45 [2] 16 47 [2] 51 56 [2] 1f 5a [2] 13 50 [2] 04 5b [2] 1f 15 [2] 22 }

  condition:
    any of them
}
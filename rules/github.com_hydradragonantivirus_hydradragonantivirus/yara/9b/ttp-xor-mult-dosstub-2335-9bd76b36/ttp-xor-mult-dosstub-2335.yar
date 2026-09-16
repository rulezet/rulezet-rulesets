rule TTP_XOR_MULT_DOSStub_2335 {
  strings:
    $key_2335 = { 77 5d [2] 03 45 [2] 44 47 [2] 03 56 [2] 4d 5a [2] 41 50 [2] 56 5b [2] 4d 15 [2] 70 }

  condition:
    any of them
}
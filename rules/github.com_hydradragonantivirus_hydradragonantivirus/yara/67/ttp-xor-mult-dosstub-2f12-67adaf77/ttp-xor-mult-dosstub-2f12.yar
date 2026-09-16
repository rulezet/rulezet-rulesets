rule TTP_XOR_MULT_DOSStub_2f12 {
  strings:
    $key_2f12 = { 7b 7a [2] 0f 62 [2] 48 60 [2] 0f 71 [2] 41 7d [2] 4d 77 [2] 5a 7c [2] 41 32 [2] 7c }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_6212 {
  strings:
    $key_6212 = { 36 7a [2] 42 62 [2] 05 60 [2] 42 71 [2] 0c 7d [2] 00 77 [2] 17 7c [2] 0c 32 [2] 31 }

  condition:
    any of them
}
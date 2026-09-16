rule TTP_XOR_MULT_DOSStub_6a12 {
  strings:
    $key_6a12 = { 3e 7a [2] 4a 62 [2] 0d 60 [2] 4a 71 [2] 04 7d [2] 08 77 [2] 1f 7c [2] 04 32 [2] 39 }

  condition:
    any of them
}
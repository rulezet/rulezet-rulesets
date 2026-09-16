rule TTP_XOR_MULT_DOSStub_5712 {
  strings:
    $key_5712 = { 03 7a [2] 77 62 [2] 30 60 [2] 77 71 [2] 39 7d [2] 35 77 [2] 22 7c [2] 39 32 [2] 04 }

  condition:
    any of them
}
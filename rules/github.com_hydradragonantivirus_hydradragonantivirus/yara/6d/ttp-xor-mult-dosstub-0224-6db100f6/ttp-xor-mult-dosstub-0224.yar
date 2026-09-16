rule TTP_XOR_MULT_DOSStub_0224 {
  strings:
    $key_0224 = { 56 4c [2] 22 54 [2] 65 56 [2] 22 47 [2] 6c 4b [2] 60 41 [2] 77 4a [2] 6c 04 [2] 51 }

  condition:
    any of them
}
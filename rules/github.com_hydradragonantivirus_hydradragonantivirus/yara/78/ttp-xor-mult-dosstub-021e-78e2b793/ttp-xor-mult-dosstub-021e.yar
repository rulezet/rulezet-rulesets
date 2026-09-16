rule TTP_XOR_MULT_DOSStub_021e {
  strings:
    $key_021e = { 56 76 [2] 22 6e [2] 65 6c [2] 22 7d [2] 6c 71 [2] 60 7b [2] 77 70 [2] 6c 3e [2] 51 }

  condition:
    any of them
}
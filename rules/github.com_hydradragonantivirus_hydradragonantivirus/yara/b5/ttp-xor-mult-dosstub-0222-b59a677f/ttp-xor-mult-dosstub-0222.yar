rule TTP_XOR_MULT_DOSStub_0222 {
  strings:
    $key_0222 = { 56 4a [2] 22 52 [2] 65 50 [2] 22 41 [2] 6c 4d [2] 60 47 [2] 77 4c [2] 6c 02 [2] 51 }

  condition:
    any of them
}
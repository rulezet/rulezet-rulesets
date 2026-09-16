rule TTP_XOR_MULT_DOSStub_0208 {
  strings:
    $key_0208 = { 56 60 [2] 22 78 [2] 65 7a [2] 22 6b [2] 6c 67 [2] 60 6d [2] 77 66 [2] 6c 28 [2] 51 }

  condition:
    any of them
}
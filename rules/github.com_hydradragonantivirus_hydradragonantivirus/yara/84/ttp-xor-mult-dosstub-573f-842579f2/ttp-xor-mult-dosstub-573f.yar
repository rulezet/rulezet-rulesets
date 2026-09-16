rule TTP_XOR_MULT_DOSStub_573f {
  strings:
    $key_573f = { 03 57 [2] 77 4f [2] 30 4d [2] 77 5c [2] 39 50 [2] 35 5a [2] 22 51 [2] 39 1f [2] 04 }

  condition:
    any of them
}
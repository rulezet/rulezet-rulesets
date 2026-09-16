rule TTP_XOR_MULT_DOSStub_233f {
  strings:
    $key_233f = { 77 57 [2] 03 4f [2] 44 4d [2] 03 5c [2] 4d 50 [2] 41 5a [2] 56 51 [2] 4d 1f [2] 70 }

  condition:
    any of them
}
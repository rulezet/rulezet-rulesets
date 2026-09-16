rule TTP_XOR_MULT_DOSStub_57e3 {
  strings:
    $key_57e3 = { 03 8b [2] 77 93 [2] 30 91 [2] 77 80 [2] 39 8c [2] 35 86 [2] 22 8d [2] 39 c3 [2] 04 }

  condition:
    any of them
}
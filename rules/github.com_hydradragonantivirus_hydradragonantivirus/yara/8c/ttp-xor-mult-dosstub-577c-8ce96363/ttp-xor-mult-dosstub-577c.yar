rule TTP_XOR_MULT_DOSStub_577c {
  strings:
    $key_577c = { 03 14 [2] 77 0c [2] 30 0e [2] 77 1f [2] 39 13 [2] 35 19 [2] 22 12 [2] 39 5c [2] 04 }

  condition:
    any of them
}
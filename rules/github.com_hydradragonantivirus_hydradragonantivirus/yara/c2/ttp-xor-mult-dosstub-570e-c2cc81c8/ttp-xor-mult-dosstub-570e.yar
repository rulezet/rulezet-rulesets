rule TTP_XOR_MULT_DOSStub_570e {
  strings:
    $key_570e = { 03 66 [2] 77 7e [2] 30 7c [2] 77 6d [2] 39 61 [2] 35 6b [2] 22 60 [2] 39 2e [2] 04 }

  condition:
    any of them
}
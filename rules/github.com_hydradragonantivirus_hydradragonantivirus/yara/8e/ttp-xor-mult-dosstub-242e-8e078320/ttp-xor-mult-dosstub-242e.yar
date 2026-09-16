rule TTP_XOR_MULT_DOSStub_242e {
  strings:
    $key_242e = { 70 46 [2] 04 5e [2] 43 5c [2] 04 4d [2] 4a 41 [2] 46 4b [2] 51 40 [2] 4a 0e [2] 77 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_102e {
  strings:
    $key_102e = { 44 46 [2] 30 5e [2] 77 5c [2] 30 4d [2] 7e 41 [2] 72 4b [2] 65 40 [2] 7e 0e [2] 43 }

  condition:
    any of them
}
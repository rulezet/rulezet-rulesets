rule TTP_XOR_MULT_DOSStub_6d2e {
  strings:
    $key_6d2e = { 39 46 [2] 4d 5e [2] 0a 5c [2] 4d 4d [2] 03 41 [2] 0f 4b [2] 18 40 [2] 03 0e [2] 3e }

  condition:
    any of them
}
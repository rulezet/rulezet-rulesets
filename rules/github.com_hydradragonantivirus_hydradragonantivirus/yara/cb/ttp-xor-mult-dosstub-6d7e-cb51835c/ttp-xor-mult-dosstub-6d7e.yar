rule TTP_XOR_MULT_DOSStub_6d7e {
  strings:
    $key_6d7e = { 39 16 [2] 4d 0e [2] 0a 0c [2] 4d 1d [2] 03 11 [2] 0f 1b [2] 18 10 [2] 03 5e [2] 3e }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_6d0e {
  strings:
    $key_6d0e = { 39 66 [2] 4d 7e [2] 0a 7c [2] 4d 6d [2] 03 61 [2] 0f 6b [2] 18 60 [2] 03 2e [2] 3e }

  condition:
    any of them
}
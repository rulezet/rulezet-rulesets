rule TTP_XOR_MULT_DOSStub_6a0e {
  strings:
    $key_6a0e = { 3e 66 [2] 4a 7e [2] 0d 7c [2] 4a 6d [2] 04 61 [2] 08 6b [2] 1f 60 [2] 04 2e [2] 39 }

  condition:
    any of them
}
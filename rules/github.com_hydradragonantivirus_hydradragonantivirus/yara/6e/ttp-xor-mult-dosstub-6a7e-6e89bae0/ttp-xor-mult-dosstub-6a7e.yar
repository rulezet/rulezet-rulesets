rule TTP_XOR_MULT_DOSStub_6a7e {
  strings:
    $key_6a7e = { 3e 16 [2] 4a 0e [2] 0d 0c [2] 4a 1d [2] 04 11 [2] 08 1b [2] 1f 10 [2] 04 5e [2] 39 }

  condition:
    any of them
}
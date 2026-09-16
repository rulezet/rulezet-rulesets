rule TTP_XOR_MULT_DOSStub_6a2e {
  strings:
    $key_6a2e = { 3e 46 [2] 4a 5e [2] 0d 5c [2] 4a 4d [2] 04 41 [2] 08 4b [2] 1f 40 [2] 04 0e [2] 39 }

  condition:
    any of them
}
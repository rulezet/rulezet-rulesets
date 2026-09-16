rule TTP_XOR_MULT_DOSStub_6a1e {
  strings:
    $key_6a1e = { 3e 76 [2] 4a 6e [2] 0d 6c [2] 4a 7d [2] 04 71 [2] 08 7b [2] 1f 70 [2] 04 3e [2] 39 }

  condition:
    any of them
}
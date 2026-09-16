rule TTP_XOR_MULT_DOSStub_081e {
  strings:
    $key_081e = { 5c 76 [2] 28 6e [2] 6f 6c [2] 28 7d [2] 66 71 [2] 6a 7b [2] 7d 70 [2] 66 3e [2] 5b }

  condition:
    any of them
}
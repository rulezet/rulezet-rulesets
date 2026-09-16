rule TTP_XOR_MULT_DOSStub_124c {
  strings:
    $key_124c = { 46 24 [2] 32 3c [2] 75 3e [2] 32 2f [2] 7c 23 [2] 70 29 [2] 67 22 [2] 7c 6c [2] 41 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_653e {
  strings:
    $key_653e = { 31 56 [2] 45 4e [2] 02 4c [2] 45 5d [2] 0b 51 [2] 07 5b [2] 10 50 [2] 0b 1e [2] 36 }

  condition:
    any of them
}
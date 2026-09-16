rule TTP_XOR_MULT_DOSStub_0aec {
  strings:
    $key_0aec = { 5e 84 [2] 2a 9c [2] 6d 9e [2] 2a 8f [2] 64 83 [2] 68 89 [2] 7f 82 [2] 64 cc [2] 59 }

  condition:
    any of them
}
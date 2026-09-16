rule TTP_XOR_MULT_DOSStub_f71b {
  strings:
    $key_f71b = { a3 73 [2] d7 6b [2] 90 69 [2] d7 78 [2] 99 74 [2] 95 7e [2] 82 75 [2] 99 3b [2] a4 }

  condition:
    any of them
}
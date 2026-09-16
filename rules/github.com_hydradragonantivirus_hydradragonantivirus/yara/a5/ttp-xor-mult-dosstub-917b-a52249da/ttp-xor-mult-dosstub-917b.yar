rule TTP_XOR_MULT_DOSStub_917b {
  strings:
    $key_917b = { c5 13 [2] b1 0b [2] f6 09 [2] b1 18 [2] ff 14 [2] f3 1e [2] e4 15 [2] ff 5b [2] c2 }

  condition:
    any of them
}
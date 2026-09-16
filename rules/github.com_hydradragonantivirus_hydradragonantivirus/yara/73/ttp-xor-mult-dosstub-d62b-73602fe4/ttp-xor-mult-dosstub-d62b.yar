rule TTP_XOR_MULT_DOSStub_d62b {
  strings:
    $key_d62b = { 82 43 [2] f6 5b [2] b1 59 [2] f6 48 [2] b8 44 [2] b4 4e [2] a3 45 [2] b8 0b [2] 85 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_e52b {
  strings:
    $key_e52b = { b1 43 [2] c5 5b [2] 82 59 [2] c5 48 [2] 8b 44 [2] 87 4e [2] 90 45 [2] 8b 0b [2] b6 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_e5ee {
  strings:
    $key_e5ee = { b1 86 [2] c5 9e [2] 82 9c [2] c5 8d [2] 8b 81 [2] 87 8b [2] 90 80 [2] 8b ce [2] b6 }

  condition:
    any of them
}
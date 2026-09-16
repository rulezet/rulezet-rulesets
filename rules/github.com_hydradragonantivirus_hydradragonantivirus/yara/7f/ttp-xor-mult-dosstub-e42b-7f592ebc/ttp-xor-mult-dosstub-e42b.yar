rule TTP_XOR_MULT_DOSStub_e42b {
  strings:
    $key_e42b = { b0 43 [2] c4 5b [2] 83 59 [2] c4 48 [2] 8a 44 [2] 86 4e [2] 91 45 [2] 8a 0b [2] b7 }

  condition:
    any of them
}
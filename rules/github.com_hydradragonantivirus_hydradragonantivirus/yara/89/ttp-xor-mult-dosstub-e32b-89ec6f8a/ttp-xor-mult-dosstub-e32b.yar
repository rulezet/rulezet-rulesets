rule TTP_XOR_MULT_DOSStub_e32b {
  strings:
    $key_e32b = { b7 43 [2] c3 5b [2] 84 59 [2] c3 48 [2] 8d 44 [2] 81 4e [2] 96 45 [2] 8d 0b [2] b0 }

  condition:
    any of them
}
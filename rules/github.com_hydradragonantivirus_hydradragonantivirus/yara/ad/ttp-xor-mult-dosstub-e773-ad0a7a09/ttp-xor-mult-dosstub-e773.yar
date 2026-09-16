rule TTP_XOR_MULT_DOSStub_e773 {
  strings:
    $key_e773 = { b3 1b [2] c7 03 [2] 80 01 [2] c7 10 [2] 89 1c [2] 85 16 [2] 92 1d [2] 89 53 [2] b4 }

  condition:
    any of them
}
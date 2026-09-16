rule TTP_XOR_MULT_DOSStub_f064 {
  strings:
    $key_f064 = { a4 0c [2] d0 14 [2] 97 16 [2] d0 07 [2] 9e 0b [2] 92 01 [2] 85 0a [2] 9e 44 [2] a3 }

  condition:
    any of them
}
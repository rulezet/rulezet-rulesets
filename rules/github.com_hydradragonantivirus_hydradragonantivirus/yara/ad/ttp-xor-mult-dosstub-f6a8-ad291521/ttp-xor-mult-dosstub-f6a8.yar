rule TTP_XOR_MULT_DOSStub_f6a8 {
  strings:
    $key_f6a8 = { a2 c0 [2] d6 d8 [2] 91 da [2] d6 cb [2] 98 c7 [2] 94 cd [2] 83 c6 [2] 98 88 [2] a5 }

  condition:
    any of them
}
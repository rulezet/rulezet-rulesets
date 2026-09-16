rule TTP_XOR_MULT_DOSStub_f023 {
  strings:
    $key_f023 = { a4 4b [2] d0 53 [2] 97 51 [2] d0 40 [2] 9e 4c [2] 92 46 [2] 85 4d [2] 9e 03 [2] a3 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f029 {
  strings:
    $key_f029 = { a4 41 [2] d0 59 [2] 97 5b [2] d0 4a [2] 9e 46 [2] 92 4c [2] 85 47 [2] 9e 09 [2] a3 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f629 {
  strings:
    $key_f629 = { a2 41 [2] d6 59 [2] 91 5b [2] d6 4a [2] 98 46 [2] 94 4c [2] 83 47 [2] 98 09 [2] a5 }

  condition:
    any of them
}
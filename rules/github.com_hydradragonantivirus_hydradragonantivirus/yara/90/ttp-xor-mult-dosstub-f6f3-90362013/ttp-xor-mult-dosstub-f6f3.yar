rule TTP_XOR_MULT_DOSStub_f6f3 {
  strings:
    $key_f6f3 = { a2 9b [2] d6 83 [2] 91 81 [2] d6 90 [2] 98 9c [2] 94 96 [2] 83 9d [2] 98 d3 [2] a5 }

  condition:
    any of them
}
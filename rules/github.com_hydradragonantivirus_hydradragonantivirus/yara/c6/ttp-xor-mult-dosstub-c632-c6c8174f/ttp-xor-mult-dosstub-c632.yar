rule TTP_XOR_MULT_DOSStub_c632 {
  strings:
    $key_c632 = { 92 5a [2] e6 42 [2] a1 40 [2] e6 51 [2] a8 5d [2] a4 57 [2] b3 5c [2] a8 12 [2] 95 }

  condition:
    any of them
}
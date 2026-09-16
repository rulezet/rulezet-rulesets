rule TTP_XOR_MULT_DOSStub_c214 {
  strings:
    $key_c214 = { 96 7c [2] e2 64 [2] a5 66 [2] e2 77 [2] ac 7b [2] a0 71 [2] b7 7a [2] ac 34 [2] 91 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f612 {
  strings:
    $key_f612 = { a2 7a [2] d6 62 [2] 91 60 [2] d6 71 [2] 98 7d [2] 94 77 [2] 83 7c [2] 98 32 [2] a5 }

  condition:
    any of them
}
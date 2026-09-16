rule TTP_XOR_MULT_DOSStub_e219 {
  strings:
    $key_e219 = { b6 71 [2] c2 69 [2] 85 6b [2] c2 7a [2] 8c 76 [2] 80 7c [2] 97 77 [2] 8c 39 [2] b1 }

  condition:
    any of them
}
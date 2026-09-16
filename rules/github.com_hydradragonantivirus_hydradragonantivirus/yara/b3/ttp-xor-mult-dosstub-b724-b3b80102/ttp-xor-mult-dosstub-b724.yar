rule TTP_XOR_MULT_DOSStub_b724 {
  strings:
    $key_b724 = { e3 4c [2] 97 54 [2] d0 56 [2] 97 47 [2] d9 4b [2] d5 41 [2] c2 4a [2] d9 04 [2] e4 }

  condition:
    any of them
}
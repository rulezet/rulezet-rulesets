rule TTP_XOR_MULT_DOSStub_b7ef {
  strings:
    $key_b7ef = { e3 87 [2] 97 9f [2] d0 9d [2] 97 8c [2] d9 80 [2] d5 8a [2] c2 81 [2] d9 cf [2] e4 }

  condition:
    any of them
}
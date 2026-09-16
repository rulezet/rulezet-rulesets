rule TTP_XOR_MULT_DOSStub_b262 {
  strings:
    $key_b262 = { e6 0a [2] 92 12 [2] d5 10 [2] 92 01 [2] dc 0d [2] d0 07 [2] c7 0c [2] dc 42 [2] e1 }

  condition:
    any of them
}
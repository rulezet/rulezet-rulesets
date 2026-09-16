rule TTP_XOR_MULT_DOSStub_b223 {
  strings:
    $key_b223 = { e6 4b [2] 92 53 [2] d5 51 [2] 92 40 [2] dc 4c [2] d0 46 [2] c7 4d [2] dc 03 [2] e1 }

  condition:
    any of them
}
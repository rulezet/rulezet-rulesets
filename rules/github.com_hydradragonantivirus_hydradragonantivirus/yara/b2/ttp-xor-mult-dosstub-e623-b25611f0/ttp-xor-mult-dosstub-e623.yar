rule TTP_XOR_MULT_DOSStub_e623 {
  strings:
    $key_e623 = { b2 4b [2] c6 53 [2] 81 51 [2] c6 40 [2] 88 4c [2] 84 46 [2] 93 4d [2] 88 03 [2] b5 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_e735 {
  strings:
    $key_e735 = { b3 5d [2] c7 45 [2] 80 47 [2] c7 56 [2] 89 5a [2] 85 50 [2] 92 5b [2] 89 15 [2] b4 }

  condition:
    any of them
}
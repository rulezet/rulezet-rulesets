rule TTP_XOR_MULT_DOSStub_38e3 {
  strings:
    $key_38e3 = { 6c 8b [2] 18 93 [2] 5f 91 [2] 18 80 [2] 56 8c [2] 5a 86 [2] 4d 8d [2] 56 c3 [2] 6b }

  condition:
    any of them
}
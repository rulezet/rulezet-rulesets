rule TTP_XOR_MULT_DOSStub_2de3 {
  strings:
    $key_2de3 = { 79 8b [2] 0d 93 [2] 4a 91 [2] 0d 80 [2] 43 8c [2] 4f 86 [2] 58 8d [2] 43 c3 [2] 7e }

  condition:
    any of them
}
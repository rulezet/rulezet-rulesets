rule TTP_XOR_MULT_DOSStub_2de1 {
  strings:
    $key_2de1 = { 79 89 [2] 0d 91 [2] 4a 93 [2] 0d 82 [2] 43 8e [2] 4f 84 [2] 58 8f [2] 43 c1 [2] 7e }

  condition:
    any of them
}
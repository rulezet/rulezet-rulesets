rule TTP_XOR_MULT_DOSStub_2f35 {
  strings:
    $key_2f35 = { 7b 5d [2] 0f 45 [2] 48 47 [2] 0f 56 [2] 41 5a [2] 4d 50 [2] 5a 5b [2] 41 15 [2] 7c }

  condition:
    any of them
}
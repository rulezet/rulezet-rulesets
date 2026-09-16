rule TTP_XOR_MULT_DOSStub_3f35 {
  strings:
    $key_3f35 = { 6b 5d [2] 1f 45 [2] 58 47 [2] 1f 56 [2] 51 5a [2] 5d 50 [2] 4a 5b [2] 51 15 [2] 6c }

  condition:
    any of them
}
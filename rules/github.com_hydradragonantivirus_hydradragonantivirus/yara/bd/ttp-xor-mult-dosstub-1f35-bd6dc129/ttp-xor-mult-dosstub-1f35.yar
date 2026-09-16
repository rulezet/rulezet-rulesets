rule TTP_XOR_MULT_DOSStub_1f35 {
  strings:
    $key_1f35 = { 4b 5d [2] 3f 45 [2] 78 47 [2] 3f 56 [2] 71 5a [2] 7d 50 [2] 6a 5b [2] 71 15 [2] 4c }

  condition:
    any of them
}
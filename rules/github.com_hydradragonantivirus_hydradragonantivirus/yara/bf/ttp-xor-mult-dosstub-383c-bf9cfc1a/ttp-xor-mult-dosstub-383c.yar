rule TTP_XOR_MULT_DOSStub_383c {
  strings:
    $key_383c = { 6c 54 [2] 18 4c [2] 5f 4e [2] 18 5f [2] 56 53 [2] 5a 59 [2] 4d 52 [2] 56 1c [2] 6b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_5035 {
  strings:
    $key_5035 = { 04 5d [2] 70 45 [2] 37 47 [2] 70 56 [2] 3e 5a [2] 32 50 [2] 25 5b [2] 3e 15 [2] 03 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_0810 {
  strings:
    $key_0810 = { 5c 78 [2] 28 60 [2] 6f 62 [2] 28 73 [2] 66 7f [2] 6a 75 [2] 7d 7e [2] 66 30 [2] 5b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_5ee3 {
  strings:
    $key_5ee3 = { 0a 8b [2] 7e 93 [2] 39 91 [2] 7e 80 [2] 30 8c [2] 3c 86 [2] 2b 8d [2] 30 c3 [2] 0d }

  condition:
    any of them
}
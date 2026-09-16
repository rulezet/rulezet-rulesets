rule TTP_XOR_MULT_DOSStub_3ee3 {
  strings:
    $key_3ee3 = { 6a 8b [2] 1e 93 [2] 59 91 [2] 1e 80 [2] 50 8c [2] 5c 86 [2] 4b 8d [2] 50 c3 [2] 6d }

  condition:
    any of them
}
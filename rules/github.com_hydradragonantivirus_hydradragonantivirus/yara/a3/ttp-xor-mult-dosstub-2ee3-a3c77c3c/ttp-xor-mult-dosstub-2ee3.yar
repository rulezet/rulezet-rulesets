rule TTP_XOR_MULT_DOSStub_2ee3 {
  strings:
    $key_2ee3 = { 7a 8b [2] 0e 93 [2] 49 91 [2] 0e 80 [2] 40 8c [2] 4c 86 [2] 5b 8d [2] 40 c3 [2] 7d }

  condition:
    any of them
}
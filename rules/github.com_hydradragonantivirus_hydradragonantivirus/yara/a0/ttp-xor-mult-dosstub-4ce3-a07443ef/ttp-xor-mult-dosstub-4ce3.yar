rule TTP_XOR_MULT_DOSStub_4ce3 {
  strings:
    $key_4ce3 = { 18 8b [2] 6c 93 [2] 2b 91 [2] 6c 80 [2] 22 8c [2] 2e 86 [2] 39 8d [2] 22 c3 [2] 1f }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_5ce3 {
  strings:
    $key_5ce3 = { 08 8b [2] 7c 93 [2] 3b 91 [2] 7c 80 [2] 32 8c [2] 3e 86 [2] 29 8d [2] 32 c3 [2] 0f }

  condition:
    any of them
}
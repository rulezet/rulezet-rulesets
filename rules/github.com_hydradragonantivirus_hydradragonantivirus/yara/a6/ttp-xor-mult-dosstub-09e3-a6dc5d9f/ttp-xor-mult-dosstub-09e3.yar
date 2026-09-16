rule TTP_XOR_MULT_DOSStub_09e3 {
  strings:
    $key_09e3 = { 5d 8b [2] 29 93 [2] 6e 91 [2] 29 80 [2] 67 8c [2] 6b 86 [2] 7c 8d [2] 67 c3 [2] 5a }

  condition:
    any of them
}
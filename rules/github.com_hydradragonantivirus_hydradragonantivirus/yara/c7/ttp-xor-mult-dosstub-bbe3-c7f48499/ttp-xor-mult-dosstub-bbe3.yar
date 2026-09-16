rule TTP_XOR_MULT_DOSStub_bbe3 {
  strings:
    $key_bbe3 = { ef 8b [2] 9b 93 [2] dc 91 [2] 9b 80 [2] d5 8c [2] d9 86 [2] ce 8d [2] d5 c3 [2] e8 }

  condition:
    any of them
}
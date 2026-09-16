rule TTP_XOR_MULT_DOSStub_bbe5 {
  strings:
    $key_bbe5 = { ef 8d [2] 9b 95 [2] dc 97 [2] 9b 86 [2] d5 8a [2] d9 80 [2] ce 8b [2] d5 c5 [2] e8 }

  condition:
    any of them
}
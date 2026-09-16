rule TTP_XOR_MULT_DOSStub_bbf4 {
  strings:
    $key_bbf4 = { ef 9c [2] 9b 84 [2] dc 86 [2] 9b 97 [2] d5 9b [2] d9 91 [2] ce 9a [2] d5 d4 [2] e8 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bbf9 {
  strings:
    $key_bbf9 = { ef 91 [2] 9b 89 [2] dc 8b [2] 9b 9a [2] d5 96 [2] d9 9c [2] ce 97 [2] d5 d9 [2] e8 }

  condition:
    any of them
}
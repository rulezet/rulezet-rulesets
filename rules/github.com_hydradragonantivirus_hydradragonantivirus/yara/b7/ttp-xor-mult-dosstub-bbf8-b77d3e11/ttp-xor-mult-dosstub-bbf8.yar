rule TTP_XOR_MULT_DOSStub_bbf8 {
  strings:
    $key_bbf8 = { ef 90 [2] 9b 88 [2] dc 8a [2] 9b 9b [2] d5 97 [2] d9 9d [2] ce 96 [2] d5 d8 [2] e8 }

  condition:
    any of them
}
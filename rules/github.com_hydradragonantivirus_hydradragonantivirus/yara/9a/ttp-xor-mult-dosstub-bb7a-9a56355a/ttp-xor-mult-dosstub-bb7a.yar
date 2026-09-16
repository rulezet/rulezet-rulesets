rule TTP_XOR_MULT_DOSStub_bb7a {
  strings:
    $key_bb7a = { ef 12 [2] 9b 0a [2] dc 08 [2] 9b 19 [2] d5 15 [2] d9 1f [2] ce 14 [2] d5 5a [2] e8 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bb0a {
  strings:
    $key_bb0a = { ef 62 [2] 9b 7a [2] dc 78 [2] 9b 69 [2] d5 65 [2] d9 6f [2] ce 64 [2] d5 2a [2] e8 }

  condition:
    any of them
}
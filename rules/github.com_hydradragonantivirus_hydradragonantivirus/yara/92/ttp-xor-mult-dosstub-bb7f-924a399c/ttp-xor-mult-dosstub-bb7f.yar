rule TTP_XOR_MULT_DOSStub_bb7f {
  strings:
    $key_bb7f = { ef 17 [2] 9b 0f [2] dc 0d [2] 9b 1c [2] d5 10 [2] d9 1a [2] ce 11 [2] d5 5f [2] e8 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bb2f {
  strings:
    $key_bb2f = { ef 47 [2] 9b 5f [2] dc 5d [2] 9b 4c [2] d5 40 [2] d9 4a [2] ce 41 [2] d5 0f [2] e8 }

  condition:
    any of them
}
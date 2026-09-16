rule TTP_XOR_MULT_DOSStub_bb1c {
  strings:
    $key_bb1c = { ef 74 [2] 9b 6c [2] dc 6e [2] 9b 7f [2] d5 73 [2] d9 79 [2] ce 72 [2] d5 3c [2] e8 }

  condition:
    any of them
}
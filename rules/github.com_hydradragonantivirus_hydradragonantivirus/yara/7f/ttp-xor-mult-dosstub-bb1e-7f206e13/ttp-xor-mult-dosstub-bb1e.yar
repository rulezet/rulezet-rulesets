rule TTP_XOR_MULT_DOSStub_bb1e {
  strings:
    $key_bb1e = { ef 76 [2] 9b 6e [2] dc 6c [2] 9b 7d [2] d5 71 [2] d9 7b [2] ce 70 [2] d5 3e [2] e8 }

  condition:
    any of them
}
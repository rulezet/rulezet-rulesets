rule TTP_XOR_MULT_DOSStub_bb13 {
  strings:
    $key_bb13 = { ef 7b [2] 9b 63 [2] dc 61 [2] 9b 70 [2] d5 7c [2] d9 76 [2] ce 7d [2] d5 33 [2] e8 }

  condition:
    any of them
}
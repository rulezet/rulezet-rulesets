rule TTP_XOR_MULT_DOSStub_e2ee {
  strings:
    $key_e2ee = { b6 86 [2] c2 9e [2] 85 9c [2] c2 8d [2] 8c 81 [2] 80 8b [2] 97 80 [2] 8c ce [2] b1 }

  condition:
    any of them
}
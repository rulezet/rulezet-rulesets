rule TTP_XOR_MULT_DOSStub_26f2 {
  strings:
    $key_26f2 = { 72 9a [2] 06 82 [2] 41 80 [2] 06 91 [2] 48 9d [2] 44 97 [2] 53 9c [2] 48 d2 [2] 75 }

  condition:
    any of them
}
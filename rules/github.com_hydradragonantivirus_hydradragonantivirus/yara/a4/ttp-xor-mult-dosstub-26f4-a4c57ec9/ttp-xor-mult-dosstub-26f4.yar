rule TTP_XOR_MULT_DOSStub_26f4 {
  strings:
    $key_26f4 = { 72 9c [2] 06 84 [2] 41 86 [2] 06 97 [2] 48 9b [2] 44 91 [2] 53 9a [2] 48 d4 [2] 75 }

  condition:
    any of them
}
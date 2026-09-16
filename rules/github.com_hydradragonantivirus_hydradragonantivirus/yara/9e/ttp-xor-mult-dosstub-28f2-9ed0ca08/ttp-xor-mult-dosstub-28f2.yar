rule TTP_XOR_MULT_DOSStub_28f2 {
  strings:
    $key_28f2 = { 7c 9a [2] 08 82 [2] 4f 80 [2] 08 91 [2] 46 9d [2] 4a 97 [2] 5d 9c [2] 46 d2 [2] 7b }

  condition:
    any of them
}
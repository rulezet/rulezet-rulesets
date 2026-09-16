rule TTP_XOR_MULT_DOSStub_28f4 {
  strings:
    $key_28f4 = { 7c 9c [2] 08 84 [2] 4f 86 [2] 08 97 [2] 46 9b [2] 4a 91 [2] 5d 9a [2] 46 d4 [2] 7b }

  condition:
    any of them
}
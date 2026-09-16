rule TTP_XOR_MULT_DOSStub_09f4 {
  strings:
    $key_09f4 = { 5d 9c [2] 29 84 [2] 6e 86 [2] 29 97 [2] 67 9b [2] 6b 91 [2] 7c 9a [2] 67 d4 [2] 5a }

  condition:
    any of them
}
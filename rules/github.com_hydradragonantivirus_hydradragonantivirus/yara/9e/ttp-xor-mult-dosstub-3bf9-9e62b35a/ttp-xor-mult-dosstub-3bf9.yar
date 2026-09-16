rule TTP_XOR_MULT_DOSStub_3bf9 {
  strings:
    $key_3bf9 = { 6f 91 [2] 1b 89 [2] 5c 8b [2] 1b 9a [2] 55 96 [2] 59 9c [2] 4e 97 [2] 55 d9 [2] 68 }

  condition:
    any of them
}
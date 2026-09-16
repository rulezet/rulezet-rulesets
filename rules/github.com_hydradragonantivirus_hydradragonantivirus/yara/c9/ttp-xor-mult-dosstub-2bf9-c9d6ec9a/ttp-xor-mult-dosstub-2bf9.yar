rule TTP_XOR_MULT_DOSStub_2bf9 {
  strings:
    $key_2bf9 = { 7f 91 [2] 0b 89 [2] 4c 8b [2] 0b 9a [2] 45 96 [2] 49 9c [2] 5e 97 [2] 45 d9 [2] 78 }

  condition:
    any of them
}
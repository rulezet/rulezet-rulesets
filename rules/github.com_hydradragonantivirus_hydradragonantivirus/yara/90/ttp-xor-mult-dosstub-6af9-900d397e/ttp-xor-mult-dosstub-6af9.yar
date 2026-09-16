rule TTP_XOR_MULT_DOSStub_6af9 {
  strings:
    $key_6af9 = { 3e 91 [2] 4a 89 [2] 0d 8b [2] 4a 9a [2] 04 96 [2] 08 9c [2] 1f 97 [2] 04 d9 [2] 39 }

  condition:
    any of them
}
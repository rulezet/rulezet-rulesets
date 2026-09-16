rule TTP_XOR_MULT_DOSStub_6af4 {
  strings:
    $key_6af4 = { 3e 9c [2] 4a 84 [2] 0d 86 [2] 4a 97 [2] 04 9b [2] 08 91 [2] 1f 9a [2] 04 d4 [2] 39 }

  condition:
    any of them
}
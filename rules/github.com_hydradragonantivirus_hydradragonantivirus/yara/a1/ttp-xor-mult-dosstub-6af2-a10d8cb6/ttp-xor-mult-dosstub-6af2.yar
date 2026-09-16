rule TTP_XOR_MULT_DOSStub_6af2 {
  strings:
    $key_6af2 = { 3e 9a [2] 4a 82 [2] 0d 80 [2] 4a 91 [2] 04 9d [2] 08 97 [2] 1f 9c [2] 04 d2 [2] 39 }

  condition:
    any of them
}
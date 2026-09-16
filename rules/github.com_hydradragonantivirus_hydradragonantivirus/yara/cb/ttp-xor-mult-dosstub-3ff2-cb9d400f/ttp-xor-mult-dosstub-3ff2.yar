rule TTP_XOR_MULT_DOSStub_3ff2 {
  strings:
    $key_3ff2 = { 6b 9a [2] 1f 82 [2] 58 80 [2] 1f 91 [2] 51 9d [2] 5d 97 [2] 4a 9c [2] 51 d2 [2] 6c }

  condition:
    any of them
}
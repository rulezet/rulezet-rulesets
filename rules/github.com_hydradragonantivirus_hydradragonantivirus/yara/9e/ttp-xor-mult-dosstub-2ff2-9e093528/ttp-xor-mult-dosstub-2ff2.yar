rule TTP_XOR_MULT_DOSStub_2ff2 {
  strings:
    $key_2ff2 = { 7b 9a [2] 0f 82 [2] 48 80 [2] 0f 91 [2] 41 9d [2] 4d 97 [2] 5a 9c [2] 41 d2 [2] 7c }

  condition:
    any of them
}
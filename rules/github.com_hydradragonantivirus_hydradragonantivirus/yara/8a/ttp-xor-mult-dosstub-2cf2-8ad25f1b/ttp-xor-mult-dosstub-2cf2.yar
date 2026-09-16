rule TTP_XOR_MULT_DOSStub_2cf2 {
  strings:
    $key_2cf2 = { 78 9a [2] 0c 82 [2] 4b 80 [2] 0c 91 [2] 42 9d [2] 4e 97 [2] 59 9c [2] 42 d2 [2] 7f }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_2ef2 {
  strings:
    $key_2ef2 = { 7a 9a [2] 0e 82 [2] 49 80 [2] 0e 91 [2] 40 9d [2] 4c 97 [2] 5b 9c [2] 40 d2 [2] 7d }

  condition:
    any of them
}
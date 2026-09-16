rule TTP_XOR_MULT_DOSStub_0ef2 {
  strings:
    $key_0ef2 = { 5a 9a [2] 2e 82 [2] 69 80 [2] 2e 91 [2] 60 9d [2] 6c 97 [2] 7b 9c [2] 60 d2 [2] 5d }

  condition:
    any of them
}
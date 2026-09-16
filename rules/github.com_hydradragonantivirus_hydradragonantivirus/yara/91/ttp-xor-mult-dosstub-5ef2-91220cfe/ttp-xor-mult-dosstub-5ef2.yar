rule TTP_XOR_MULT_DOSStub_5ef2 {
  strings:
    $key_5ef2 = { 0a 9a [2] 7e 82 [2] 39 80 [2] 7e 91 [2] 30 9d [2] 3c 97 [2] 2b 9c [2] 30 d2 [2] 0d }

  condition:
    any of them
}
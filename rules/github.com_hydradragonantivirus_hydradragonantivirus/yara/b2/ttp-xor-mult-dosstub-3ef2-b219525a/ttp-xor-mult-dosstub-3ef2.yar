rule TTP_XOR_MULT_DOSStub_3ef2 {
  strings:
    $key_3ef2 = { 6a 9a [2] 1e 82 [2] 59 80 [2] 1e 91 [2] 50 9d [2] 5c 97 [2] 4b 9c [2] 50 d2 [2] 6d }

  condition:
    any of them
}
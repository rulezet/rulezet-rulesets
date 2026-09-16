rule TTP_XOR_MULT_DOSStub_3ef4 {
  strings:
    $key_3ef4 = { 6a 9c [2] 1e 84 [2] 59 86 [2] 1e 97 [2] 50 9b [2] 5c 91 [2] 4b 9a [2] 50 d4 [2] 6d }

  condition:
    any of them
}
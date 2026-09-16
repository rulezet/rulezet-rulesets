rule TTP_XOR_MULT_DOSStub_3ef9 {
  strings:
    $key_3ef9 = { 6a 91 [2] 1e 89 [2] 59 8b [2] 1e 9a [2] 50 96 [2] 5c 9c [2] 4b 97 [2] 50 d9 [2] 6d }

  condition:
    any of them
}
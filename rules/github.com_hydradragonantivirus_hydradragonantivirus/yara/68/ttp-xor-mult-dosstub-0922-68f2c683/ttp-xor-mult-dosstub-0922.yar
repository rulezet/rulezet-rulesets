rule TTP_XOR_MULT_DOSStub_0922 {
  strings:
    $key_0922 = { 5d 4a [2] 29 52 [2] 6e 50 [2] 29 41 [2] 67 4d [2] 6b 47 [2] 7c 4c [2] 67 02 [2] 5a }

  condition:
    any of them
}
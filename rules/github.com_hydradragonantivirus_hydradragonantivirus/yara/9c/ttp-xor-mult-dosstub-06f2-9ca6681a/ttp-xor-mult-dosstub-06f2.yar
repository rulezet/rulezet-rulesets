rule TTP_XOR_MULT_DOSStub_06f2 {
  strings:
    $key_06f2 = { 52 9a [2] 26 82 [2] 61 80 [2] 26 91 [2] 68 9d [2] 64 97 [2] 73 9c [2] 68 d2 [2] 55 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_6bf4 {
  strings:
    $key_6bf4 = { 3f 9c [2] 4b 84 [2] 0c 86 [2] 4b 97 [2] 05 9b [2] 09 91 [2] 1e 9a [2] 05 d4 [2] 38 }

  condition:
    any of them
}
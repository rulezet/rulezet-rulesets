rule TTP_XOR_MULT_DOSStub_0b24 {
  strings:
    $key_0b24 = { 5f 4c [2] 2b 54 [2] 6c 56 [2] 2b 47 [2] 65 4b [2] 69 41 [2] 7e 4a [2] 65 04 [2] 58 }

  condition:
    any of them
}
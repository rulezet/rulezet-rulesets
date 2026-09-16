rule TTP_XOR_MULT_DOSStub_4121 {
  strings:
    $key_4121 = { 15 49 [2] 61 51 [2] 26 53 [2] 61 42 [2] 2f 4e [2] 23 44 [2] 34 4f [2] 2f 01 [2] 12 }

  condition:
    any of them
}
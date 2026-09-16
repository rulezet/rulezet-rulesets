rule TTP_XOR_MULT_DOSStub_3f28 {
  strings:
    $key_3f28 = { 6b 40 [2] 1f 58 [2] 58 5a [2] 1f 4b [2] 51 47 [2] 5d 4d [2] 4a 46 [2] 51 08 [2] 6c }

  condition:
    any of them
}
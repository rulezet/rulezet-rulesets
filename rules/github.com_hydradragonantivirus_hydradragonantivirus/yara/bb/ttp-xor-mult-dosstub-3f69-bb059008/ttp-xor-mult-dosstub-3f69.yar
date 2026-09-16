rule TTP_XOR_MULT_DOSStub_3f69 {
  strings:
    $key_3f69 = { 6b 01 [2] 1f 19 [2] 58 1b [2] 1f 0a [2] 51 06 [2] 5d 0c [2] 4a 07 [2] 51 49 [2] 6c }

  condition:
    any of them
}
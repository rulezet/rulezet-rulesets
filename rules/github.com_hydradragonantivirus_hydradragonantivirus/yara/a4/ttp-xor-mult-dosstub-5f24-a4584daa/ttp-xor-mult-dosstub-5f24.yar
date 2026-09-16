rule TTP_XOR_MULT_DOSStub_5f24 {
  strings:
    $key_5f24 = { 0b 4c [2] 7f 54 [2] 38 56 [2] 7f 47 [2] 31 4b [2] 3d 41 [2] 2a 4a [2] 31 04 [2] 0c }

  condition:
    any of them
}
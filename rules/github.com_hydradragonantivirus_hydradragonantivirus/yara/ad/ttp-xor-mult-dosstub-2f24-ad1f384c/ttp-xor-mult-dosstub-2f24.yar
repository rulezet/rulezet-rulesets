rule TTP_XOR_MULT_DOSStub_2f24 {
  strings:
    $key_2f24 = { 7b 4c [2] 0f 54 [2] 48 56 [2] 0f 47 [2] 41 4b [2] 4d 41 [2] 5a 4a [2] 41 04 [2] 7c }

  condition:
    any of them
}
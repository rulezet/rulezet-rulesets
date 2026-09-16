rule TTP_XOR_MULT_DOSStub_2f53 {
  strings:
    $key_2f53 = { 7b 3b [2] 0f 23 [2] 48 21 [2] 0f 30 [2] 41 3c [2] 4d 36 [2] 5a 3d [2] 41 73 [2] 7c }

  condition:
    any of them
}
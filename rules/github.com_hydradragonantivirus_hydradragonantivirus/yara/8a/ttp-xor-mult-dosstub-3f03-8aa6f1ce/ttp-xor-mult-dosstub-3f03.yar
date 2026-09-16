rule TTP_XOR_MULT_DOSStub_3f03 {
  strings:
    $key_3f03 = { 6b 6b [2] 1f 73 [2] 58 71 [2] 1f 60 [2] 51 6c [2] 5d 66 [2] 4a 6d [2] 51 23 [2] 6c }

  condition:
    any of them
}
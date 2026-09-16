rule TTP_XOR_MULT_DOSStub_3f29 {
  strings:
    $key_3f29 = { 6b 41 [2] 1f 59 [2] 58 5b [2] 1f 4a [2] 51 46 [2] 5d 4c [2] 4a 47 [2] 51 09 [2] 6c }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_361f {
  strings:
    $key_361f = { 62 77 [2] 16 6f [2] 51 6d [2] 16 7c [2] 58 70 [2] 54 7a [2] 43 71 [2] 58 3f [2] 65 }

  condition:
    any of them
}
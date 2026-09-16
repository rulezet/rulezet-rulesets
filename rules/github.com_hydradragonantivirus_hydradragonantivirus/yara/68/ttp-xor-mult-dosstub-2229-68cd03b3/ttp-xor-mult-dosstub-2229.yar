rule TTP_XOR_MULT_DOSStub_2229 {
  strings:
    $key_2229 = { 76 41 [2] 02 59 [2] 45 5b [2] 02 4a [2] 4c 46 [2] 40 4c [2] 57 47 [2] 4c 09 [2] 71 }

  condition:
    any of them
}
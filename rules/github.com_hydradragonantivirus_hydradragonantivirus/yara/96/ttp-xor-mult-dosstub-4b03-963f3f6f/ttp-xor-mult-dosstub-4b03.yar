rule TTP_XOR_MULT_DOSStub_4b03 {
  strings:
    $key_4b03 = { 1f 6b [2] 6b 73 [2] 2c 71 [2] 6b 60 [2] 25 6c [2] 29 66 [2] 3e 6d [2] 25 23 [2] 18 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_3b03 {
  strings:
    $key_3b03 = { 6f 6b [2] 1b 73 [2] 5c 71 [2] 1b 60 [2] 55 6c [2] 59 66 [2] 4e 6d [2] 55 23 [2] 68 }

  condition:
    any of them
}
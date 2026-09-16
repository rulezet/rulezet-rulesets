rule TTP_XOR_MULT_DOSStub_0903 {
  strings:
    $key_0903 = { 5d 6b [2] 29 73 [2] 6e 71 [2] 29 60 [2] 67 6c [2] 6b 66 [2] 7c 6d [2] 67 23 [2] 5a }

  condition:
    any of them
}
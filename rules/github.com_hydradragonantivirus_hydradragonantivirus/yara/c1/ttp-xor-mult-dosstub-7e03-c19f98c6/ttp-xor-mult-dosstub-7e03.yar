rule TTP_XOR_MULT_DOSStub_7e03 {
  strings:
    $key_7e03 = { 2a 6b [2] 5e 73 [2] 19 71 [2] 5e 60 [2] 10 6c [2] 1c 66 [2] 0b 6d [2] 10 23 [2] 2d }

  condition:
    any of them
}
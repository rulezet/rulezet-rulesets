rule TTP_XOR_MULT_DOSStub_5e53 {
  strings:
    $key_5e53 = { 0a 3b [2] 7e 23 [2] 39 21 [2] 7e 30 [2] 30 3c [2] 3c 36 [2] 2b 3d [2] 30 73 [2] 0d }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_3e53 {
  strings:
    $key_3e53 = { 6a 3b [2] 1e 23 [2] 59 21 [2] 1e 30 [2] 50 3c [2] 5c 36 [2] 4b 3d [2] 50 73 [2] 6d }

  condition:
    any of them
}
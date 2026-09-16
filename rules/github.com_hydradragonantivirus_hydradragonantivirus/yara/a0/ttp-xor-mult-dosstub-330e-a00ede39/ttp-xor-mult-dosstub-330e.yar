rule TTP_XOR_MULT_DOSStub_330e {
  strings:
    $key_330e = { 67 66 [2] 13 7e [2] 54 7c [2] 13 6d [2] 5d 61 [2] 51 6b [2] 46 60 [2] 5d 2e [2] 60 }

  condition:
    any of them
}
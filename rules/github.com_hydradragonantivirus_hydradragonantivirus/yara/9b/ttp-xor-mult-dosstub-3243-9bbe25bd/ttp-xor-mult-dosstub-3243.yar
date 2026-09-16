rule TTP_XOR_MULT_DOSStub_3243 {
  strings:
    $key_3243 = { 66 2b [2] 12 33 [2] 55 31 [2] 12 20 [2] 5c 2c [2] 50 26 [2] 47 2d [2] 5c 63 [2] 61 }

  condition:
    any of them
}
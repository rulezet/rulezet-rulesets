rule TTP_XOR_MULT_DOSStub_0a23 {
  strings:
    $key_0a23 = { 5e 4b [2] 2a 53 [2] 6d 51 [2] 2a 40 [2] 64 4c [2] 68 46 [2] 7f 4d [2] 64 03 [2] 59 }

  condition:
    any of them
}
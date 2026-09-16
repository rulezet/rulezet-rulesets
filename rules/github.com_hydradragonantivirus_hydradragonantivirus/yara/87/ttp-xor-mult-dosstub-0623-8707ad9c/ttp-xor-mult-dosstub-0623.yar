rule TTP_XOR_MULT_DOSStub_0623 {
  strings:
    $key_0623 = { 52 4b [2] 26 53 [2] 61 51 [2] 26 40 [2] 68 4c [2] 64 46 [2] 73 4d [2] 68 03 [2] 55 }

  condition:
    any of them
}
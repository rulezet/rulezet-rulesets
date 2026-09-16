rule TTP_XOR_MULT_DOSStub_3023 {
  strings:
    $key_3023 = { 64 4b [2] 10 53 [2] 57 51 [2] 10 40 [2] 5e 4c [2] 52 46 [2] 45 4d [2] 5e 03 [2] 63 }

  condition:
    any of them
}
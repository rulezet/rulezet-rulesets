rule TTP_XOR_MULT_DOSStub_3723 {
  strings:
    $key_3723 = { 63 4b [2] 17 53 [2] 50 51 [2] 17 40 [2] 59 4c [2] 55 46 [2] 42 4d [2] 59 03 [2] 64 }

  condition:
    any of them
}
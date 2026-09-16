rule TTP_XOR_MULT_DOSStub_5023 {
  strings:
    $key_5023 = { 04 4b [2] 70 53 [2] 37 51 [2] 70 40 [2] 3e 4c [2] 32 46 [2] 25 4d [2] 3e 03 [2] 03 }

  condition:
    any of them
}
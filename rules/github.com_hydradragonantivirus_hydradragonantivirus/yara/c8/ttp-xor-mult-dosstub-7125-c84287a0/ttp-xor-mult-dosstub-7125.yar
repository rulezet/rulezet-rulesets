rule TTP_XOR_MULT_DOSStub_7125 {
  strings:
    $key_7125 = { 25 4d [2] 51 55 [2] 16 57 [2] 51 46 [2] 1f 4a [2] 13 40 [2] 04 4b [2] 1f 05 [2] 22 }

  condition:
    any of them
}
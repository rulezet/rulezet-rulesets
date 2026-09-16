rule TTP_XOR_MULT_DOSStub_6a23 {
  strings:
    $key_6a23 = { 3e 4b [2] 4a 53 [2] 0d 51 [2] 4a 40 [2] 04 4c [2] 08 46 [2] 1f 4d [2] 04 03 [2] 39 }

  condition:
    any of them
}
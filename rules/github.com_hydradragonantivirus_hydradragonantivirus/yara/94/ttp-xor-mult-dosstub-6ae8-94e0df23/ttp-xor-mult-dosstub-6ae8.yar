rule TTP_XOR_MULT_DOSStub_6ae8 {
  strings:
    $key_6ae8 = { 3e 80 [2] 4a 98 [2] 0d 9a [2] 4a 8b [2] 04 87 [2] 08 8d [2] 1f 86 [2] 04 c8 [2] 39 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_6de8 {
  strings:
    $key_6de8 = { 39 80 [2] 4d 98 [2] 0a 9a [2] 4d 8b [2] 03 87 [2] 0f 8d [2] 18 86 [2] 03 c8 [2] 3e }

  condition:
    any of them
}
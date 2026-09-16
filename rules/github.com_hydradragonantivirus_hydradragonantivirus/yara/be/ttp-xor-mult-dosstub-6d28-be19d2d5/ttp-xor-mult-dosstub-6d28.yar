rule TTP_XOR_MULT_DOSStub_6d28 {
  strings:
    $key_6d28 = { 39 40 [2] 4d 58 [2] 0a 5a [2] 4d 4b [2] 03 47 [2] 0f 4d [2] 18 46 [2] 03 08 [2] 3e }

  condition:
    any of them
}
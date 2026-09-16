rule TTP_XOR_MULT_DOSStub_2802 {
  strings:
    $key_2802 = { 7c 6a [2] 08 72 [2] 4f 70 [2] 08 61 [2] 46 6d [2] 4a 67 [2] 5d 6c [2] 46 22 [2] 7b }

  condition:
    any of them
}
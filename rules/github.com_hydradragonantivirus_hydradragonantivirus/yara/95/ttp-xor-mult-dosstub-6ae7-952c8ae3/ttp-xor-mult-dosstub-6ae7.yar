rule TTP_XOR_MULT_DOSStub_6ae7 {
  strings:
    $key_6ae7 = { 3e 8f [2] 4a 97 [2] 0d 95 [2] 4a 84 [2] 04 88 [2] 08 82 [2] 1f 89 [2] 04 c7 [2] 39 }

  condition:
    any of them
}
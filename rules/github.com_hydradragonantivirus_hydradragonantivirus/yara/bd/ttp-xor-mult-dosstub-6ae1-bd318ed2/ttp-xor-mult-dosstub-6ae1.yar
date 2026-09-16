rule TTP_XOR_MULT_DOSStub_6ae1 {
  strings:
    $key_6ae1 = { 3e 89 [2] 4a 91 [2] 0d 93 [2] 4a 82 [2] 04 8e [2] 08 84 [2] 1f 8f [2] 04 c1 [2] 39 }

  condition:
    any of them
}
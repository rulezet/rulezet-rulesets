rule TTP_XOR_MULT_DOSStub_6de1 {
  strings:
    $key_6de1 = { 39 89 [2] 4d 91 [2] 0a 93 [2] 4d 82 [2] 03 8e [2] 0f 84 [2] 18 8f [2] 03 c1 [2] 3e }

  condition:
    any of them
}
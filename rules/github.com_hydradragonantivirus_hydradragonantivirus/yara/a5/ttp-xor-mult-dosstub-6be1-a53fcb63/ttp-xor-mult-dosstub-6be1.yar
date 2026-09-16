rule TTP_XOR_MULT_DOSStub_6be1 {
  strings:
    $key_6be1 = { 3f 89 [2] 4b 91 [2] 0c 93 [2] 4b 82 [2] 05 8e [2] 09 84 [2] 1e 8f [2] 05 c1 [2] 38 }

  condition:
    any of them
}
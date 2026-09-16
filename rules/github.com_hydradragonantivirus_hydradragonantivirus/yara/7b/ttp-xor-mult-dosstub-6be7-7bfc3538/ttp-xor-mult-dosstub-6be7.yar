rule TTP_XOR_MULT_DOSStub_6be7 {
  strings:
    $key_6be7 = { 3f 8f [2] 4b 97 [2] 0c 95 [2] 4b 84 [2] 05 88 [2] 09 82 [2] 1e 89 [2] 05 c7 [2] 38 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_1f67 {
  strings:
    $key_1f67 = { 4b 0f [2] 3f 17 [2] 78 15 [2] 3f 04 [2] 71 08 [2] 7d 02 [2] 6a 09 [2] 71 47 [2] 4c }

  condition:
    any of them
}
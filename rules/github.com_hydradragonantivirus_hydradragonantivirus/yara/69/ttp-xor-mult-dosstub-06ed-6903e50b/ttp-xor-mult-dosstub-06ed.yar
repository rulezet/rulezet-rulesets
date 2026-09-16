rule TTP_XOR_MULT_DOSStub_06ed {
  strings:
    $key_06ed = { 52 85 [2] 26 9d [2] 61 9f [2] 26 8e [2] 68 82 [2] 64 88 [2] 73 83 [2] 68 cd [2] 55 }

  condition:
    any of them
}
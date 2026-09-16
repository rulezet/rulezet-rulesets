rule TTP_XOR_MULT_DOSStub_61ed {
  strings:
    $key_61ed = { 35 85 [2] 41 9d [2] 06 9f [2] 41 8e [2] 0f 82 [2] 03 88 [2] 14 83 [2] 0f cd [2] 32 }

  condition:
    any of them
}
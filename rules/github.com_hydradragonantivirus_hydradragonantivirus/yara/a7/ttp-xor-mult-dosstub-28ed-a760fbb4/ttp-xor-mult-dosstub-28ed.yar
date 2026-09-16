rule TTP_XOR_MULT_DOSStub_28ed {
  strings:
    $key_28ed = { 7c 85 [2] 08 9d [2] 4f 9f [2] 08 8e [2] 46 82 [2] 4a 88 [2] 5d 83 [2] 46 cd [2] 7b }

  condition:
    any of them
}
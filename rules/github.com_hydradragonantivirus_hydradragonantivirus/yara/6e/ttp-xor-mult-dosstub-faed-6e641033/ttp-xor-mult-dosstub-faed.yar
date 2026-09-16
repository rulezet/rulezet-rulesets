rule TTP_XOR_MULT_DOSStub_faed {
  strings:
    $key_faed = { ae 85 [2] da 9d [2] 9d 9f [2] da 8e [2] 94 82 [2] 98 88 [2] 8f 83 [2] 94 cd [2] a9 }

  condition:
    any of them
}
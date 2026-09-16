rule TTP_XOR_MULT_DOSStub_1ded {
  strings:
    $key_1ded = { 49 85 [2] 3d 9d [2] 7a 9f [2] 3d 8e [2] 73 82 [2] 7f 88 [2] 68 83 [2] 73 cd [2] 4e }

  condition:
    any of them
}
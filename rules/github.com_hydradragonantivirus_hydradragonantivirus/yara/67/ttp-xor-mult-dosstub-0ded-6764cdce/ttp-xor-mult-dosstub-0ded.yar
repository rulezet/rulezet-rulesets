rule TTP_XOR_MULT_DOSStub_0ded {
  strings:
    $key_0ded = { 59 85 [2] 2d 9d [2] 6a 9f [2] 2d 8e [2] 63 82 [2] 6f 88 [2] 78 83 [2] 63 cd [2] 5e }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_4fed {
  strings:
    $key_4fed = { 1b 85 [2] 6f 9d [2] 28 9f [2] 6f 8e [2] 21 82 [2] 2d 88 [2] 3a 83 [2] 21 cd [2] 1c }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_5fed {
  strings:
    $key_5fed = { 0b 85 [2] 7f 9d [2] 38 9f [2] 7f 8e [2] 31 82 [2] 3d 88 [2] 2a 83 [2] 31 cd [2] 0c }

  condition:
    any of them
}
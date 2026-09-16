rule TTP_XOR_MULT_DOSStub_2fed {
  strings:
    $key_2fed = { 7b 85 [2] 0f 9d [2] 48 9f [2] 0f 8e [2] 41 82 [2] 4d 88 [2] 5a 83 [2] 41 cd [2] 7c }

  condition:
    any of them
}
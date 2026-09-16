rule TTP_XOR_MULT_DOSStub_2feb {
  strings:
    $key_2feb = { 7b 83 [2] 0f 9b [2] 48 99 [2] 0f 88 [2] 41 84 [2] 4d 8e [2] 5a 85 [2] 41 cb [2] 7c }

  condition:
    any of them
}
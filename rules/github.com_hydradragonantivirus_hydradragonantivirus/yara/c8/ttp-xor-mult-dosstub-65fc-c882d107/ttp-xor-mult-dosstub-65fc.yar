rule TTP_XOR_MULT_DOSStub_65fc {
  strings:
    $key_65fc = { 31 94 [2] 45 8c [2] 02 8e [2] 45 9f [2] 0b 93 [2] 07 99 [2] 10 92 [2] 0b dc [2] 36 }

  condition:
    any of them
}
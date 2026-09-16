rule TTP_XOR_MULT_DOSStub_65f9 {
  strings:
    $key_65f9 = { 31 91 [2] 45 89 [2] 02 8b [2] 45 9a [2] 0b 96 [2] 07 9c [2] 10 97 [2] 0b d9 [2] 36 }

  condition:
    any of them
}
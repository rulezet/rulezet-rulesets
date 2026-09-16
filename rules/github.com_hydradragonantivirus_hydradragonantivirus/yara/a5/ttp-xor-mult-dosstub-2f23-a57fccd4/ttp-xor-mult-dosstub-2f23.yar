rule TTP_XOR_MULT_DOSStub_2f23 {
  strings:
    $key_2f23 = { 7b 4b [2] 0f 53 [2] 48 51 [2] 0f 40 [2] 41 4c [2] 4d 46 [2] 5a 4d [2] 41 03 [2] 7c }

  condition:
    any of them
}
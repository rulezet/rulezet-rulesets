rule TTP_XOR_MULT_DOSStub_2f64 {
  strings:
    $key_2f64 = { 7b 0c [2] 0f 14 [2] 48 16 [2] 0f 07 [2] 41 0b [2] 4d 01 [2] 5a 0a [2] 41 44 [2] 7c }

  condition:
    any of them
}
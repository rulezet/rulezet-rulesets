rule TTP_XOR_MULT_DOSStub_6f64 {
  strings:
    $key_6f64 = { 3b 0c [2] 4f 14 [2] 08 16 [2] 4f 07 [2] 01 0b [2] 0d 01 [2] 1a 0a [2] 01 44 [2] 3c }

  condition:
    any of them
}
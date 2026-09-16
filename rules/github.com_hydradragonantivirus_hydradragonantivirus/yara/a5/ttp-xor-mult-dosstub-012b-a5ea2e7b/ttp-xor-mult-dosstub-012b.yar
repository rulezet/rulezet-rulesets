rule TTP_XOR_MULT_DOSStub_012b {
  strings:
    $key_012b = { 55 43 [2] 21 5b [2] 66 59 [2] 21 48 [2] 6f 44 [2] 63 4e [2] 74 45 [2] 6f 0b [2] 52 }

  condition:
    any of them
}
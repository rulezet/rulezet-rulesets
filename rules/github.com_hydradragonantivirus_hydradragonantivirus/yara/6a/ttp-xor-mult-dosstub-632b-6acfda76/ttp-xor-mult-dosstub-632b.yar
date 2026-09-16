rule TTP_XOR_MULT_DOSStub_632b {
  strings:
    $key_632b = { 37 43 [2] 43 5b [2] 04 59 [2] 43 48 [2] 0d 44 [2] 01 4e [2] 16 45 [2] 0d 0b [2] 30 }

  condition:
    any of them
}
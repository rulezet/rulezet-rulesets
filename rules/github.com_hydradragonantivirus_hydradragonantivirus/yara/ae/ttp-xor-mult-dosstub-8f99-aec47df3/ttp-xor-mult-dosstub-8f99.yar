rule TTP_XOR_MULT_DOSStub_8f99 {
  strings:
    $key_8f99 = { db f1 [2] af e9 [2] e8 eb [2] af fa [2] e1 f6 [2] ed fc [2] fa f7 [2] e1 b9 [2] dc }

  condition:
    any of them
}
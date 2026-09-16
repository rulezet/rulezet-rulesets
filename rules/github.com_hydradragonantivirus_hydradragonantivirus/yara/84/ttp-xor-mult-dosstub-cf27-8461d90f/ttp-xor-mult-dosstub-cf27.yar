rule TTP_XOR_MULT_DOSStub_cf27 {
  strings:
    $key_cf27 = { 9b 4f [2] ef 57 [2] a8 55 [2] ef 44 [2] a1 48 [2] ad 42 [2] ba 49 [2] a1 07 [2] 9c }

  condition:
    any of them
}
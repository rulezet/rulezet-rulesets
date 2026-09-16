rule TTP_XOR_MULT_DOSStub_f8af {
  strings:
    $key_f8af = { ac c7 [2] d8 df [2] 9f dd [2] d8 cc [2] 96 c0 [2] 9a ca [2] 8d c1 [2] 96 8f [2] ab }

  condition:
    any of them
}
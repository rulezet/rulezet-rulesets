rule TTP_XOR_MULT_DOSStub_e8af {
  strings:
    $key_e8af = { bc c7 [2] c8 df [2] 8f dd [2] c8 cc [2] 86 c0 [2] 8a ca [2] 9d c1 [2] 86 8f [2] bb }

  condition:
    any of them
}
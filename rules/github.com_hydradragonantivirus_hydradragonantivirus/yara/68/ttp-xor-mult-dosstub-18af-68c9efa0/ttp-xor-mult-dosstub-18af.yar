rule TTP_XOR_MULT_DOSStub_18af {
  strings:
    $key_18af = { 4c c7 [2] 38 df [2] 7f dd [2] 38 cc [2] 76 c0 [2] 7a ca [2] 6d c1 [2] 76 8f [2] 4b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_38af {
  strings:
    $key_38af = { 6c c7 [2] 18 df [2] 5f dd [2] 18 cc [2] 56 c0 [2] 5a ca [2] 4d c1 [2] 56 8f [2] 6b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_57af {
  strings:
    $key_57af = { 03 c7 [2] 77 df [2] 30 dd [2] 77 cc [2] 39 c0 [2] 35 ca [2] 22 c1 [2] 39 8f [2] 04 }

  condition:
    any of them
}
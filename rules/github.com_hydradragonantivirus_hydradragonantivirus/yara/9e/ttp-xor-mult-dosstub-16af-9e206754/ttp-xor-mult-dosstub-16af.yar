rule TTP_XOR_MULT_DOSStub_16af {
  strings:
    $key_16af = { 42 c7 [2] 36 df [2] 71 dd [2] 36 cc [2] 78 c0 [2] 74 ca [2] 63 c1 [2] 78 8f [2] 45 }

  condition:
    any of them
}
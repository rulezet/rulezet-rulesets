rule TTP_XOR_MULT_DOSStub_7aaf {
  strings:
    $key_7aaf = { 2e c7 [2] 5a df [2] 1d dd [2] 5a cc [2] 14 c0 [2] 18 ca [2] 0f c1 [2] 14 8f [2] 29 }

  condition:
    any of them
}
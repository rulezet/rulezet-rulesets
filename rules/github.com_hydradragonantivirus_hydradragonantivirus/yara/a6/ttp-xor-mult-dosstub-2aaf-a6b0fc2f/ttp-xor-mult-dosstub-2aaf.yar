rule TTP_XOR_MULT_DOSStub_2aaf {
  strings:
    $key_2aaf = { 7e c7 [2] 0a df [2] 4d dd [2] 0a cc [2] 44 c0 [2] 48 ca [2] 5f c1 [2] 44 8f [2] 79 }

  condition:
    any of them
}
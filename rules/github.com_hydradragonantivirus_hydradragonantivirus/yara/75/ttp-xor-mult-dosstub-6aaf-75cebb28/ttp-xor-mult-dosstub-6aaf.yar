rule TTP_XOR_MULT_DOSStub_6aaf {
  strings:
    $key_6aaf = { 3e c7 [2] 4a df [2] 0d dd [2] 4a cc [2] 04 c0 [2] 08 ca [2] 1f c1 [2] 04 8f [2] 39 }

  condition:
    any of them
}
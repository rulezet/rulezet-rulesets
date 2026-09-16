rule TTP_XOR_MULT_DOSStub_fbcf {
  strings:
    $key_fbcf = { af a7 [2] db bf [2] 9c bd [2] db ac [2] 95 a0 [2] 99 aa [2] 8e a1 [2] 95 ef [2] a8 }

  condition:
    any of them
}
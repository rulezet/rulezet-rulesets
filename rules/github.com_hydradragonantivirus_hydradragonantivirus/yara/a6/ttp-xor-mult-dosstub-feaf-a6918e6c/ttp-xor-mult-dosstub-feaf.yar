rule TTP_XOR_MULT_DOSStub_feaf {
  strings:
    $key_feaf = { aa c7 [2] de df [2] 99 dd [2] de cc [2] 90 c0 [2] 9c ca [2] 8b c1 [2] 90 8f [2] ad }

  condition:
    any of them
}
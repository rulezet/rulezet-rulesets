rule TTP_XOR_MULT_DOSStub_2ccd {
  strings:
    $key_2ccd = { 78 a5 [2] 0c bd [2] 4b bf [2] 0c ae [2] 42 a2 [2] 4e a8 [2] 59 a3 [2] 42 ed [2] 7f }

  condition:
    any of them
}
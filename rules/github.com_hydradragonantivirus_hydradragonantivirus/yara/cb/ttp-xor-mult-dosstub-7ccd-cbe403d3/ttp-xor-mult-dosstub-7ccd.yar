rule TTP_XOR_MULT_DOSStub_7ccd {
  strings:
    $key_7ccd = { 28 a5 [2] 5c bd [2] 1b bf [2] 5c ae [2] 12 a2 [2] 1e a8 [2] 09 a3 [2] 12 ed [2] 2f }

  condition:
    any of them
}
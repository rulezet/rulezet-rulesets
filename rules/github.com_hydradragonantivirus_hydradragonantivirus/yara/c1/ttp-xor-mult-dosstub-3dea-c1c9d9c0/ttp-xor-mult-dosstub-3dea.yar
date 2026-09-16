rule TTP_XOR_MULT_DOSStub_3dea {
  strings:
    $key_3dea = { 69 82 [2] 1d 9a [2] 5a 98 [2] 1d 89 [2] 53 85 [2] 5f 8f [2] 48 84 [2] 53 ca [2] 6e }

  condition:
    any of them
}
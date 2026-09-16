rule TTP_XOR_MULT_DOSStub_1baf {
  strings:
    $key_1baf = { 4f c7 [2] 3b df [2] 7c dd [2] 3b cc [2] 75 c0 [2] 79 ca [2] 6e c1 [2] 75 8f [2] 48 }

  condition:
    any of them
}
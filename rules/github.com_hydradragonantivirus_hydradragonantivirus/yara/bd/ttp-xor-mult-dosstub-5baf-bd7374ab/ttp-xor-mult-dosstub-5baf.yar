rule TTP_XOR_MULT_DOSStub_5baf {
  strings:
    $key_5baf = { 0f c7 [2] 7b df [2] 3c dd [2] 7b cc [2] 35 c0 [2] 39 ca [2] 2e c1 [2] 35 8f [2] 08 }

  condition:
    any of them
}
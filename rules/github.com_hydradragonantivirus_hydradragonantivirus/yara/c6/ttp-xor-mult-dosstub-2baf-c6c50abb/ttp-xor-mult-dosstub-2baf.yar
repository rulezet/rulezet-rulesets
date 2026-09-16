rule TTP_XOR_MULT_DOSStub_2baf {
  strings:
    $key_2baf = { 7f c7 [2] 0b df [2] 4c dd [2] 0b cc [2] 45 c0 [2] 49 ca [2] 5e c1 [2] 45 8f [2] 78 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_abaf {
  strings:
    $key_abaf = { ff c7 [2] 8b df [2] cc dd [2] 8b cc [2] c5 c0 [2] c9 ca [2] de c1 [2] c5 8f [2] f8 }

  condition:
    any of them
}
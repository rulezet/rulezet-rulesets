rule TTP_XOR_MULT_DOSStub_bbaf {
  strings:
    $key_bbaf = { ef c7 [2] 9b df [2] dc dd [2] 9b cc [2] d5 c0 [2] d9 ca [2] ce c1 [2] d5 8f [2] e8 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_ad69 {
  strings:
    $key_ad69 = { f9 01 [2] 8d 19 [2] ca 1b [2] 8d 0a [2] c3 06 [2] cf 0c [2] d8 07 [2] c3 49 [2] fe }

  condition:
    any of them
}
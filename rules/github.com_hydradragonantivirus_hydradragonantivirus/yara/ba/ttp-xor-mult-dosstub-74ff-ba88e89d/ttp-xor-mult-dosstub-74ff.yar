rule TTP_XOR_MULT_DOSStub_74ff {
  strings:
    $key_74ff = { 20 97 [2] 54 8f [2] 13 8d [2] 54 9c [2] 1a 90 [2] 16 9a [2] 01 91 [2] 1a df [2] 27 }

  condition:
    any of them
}
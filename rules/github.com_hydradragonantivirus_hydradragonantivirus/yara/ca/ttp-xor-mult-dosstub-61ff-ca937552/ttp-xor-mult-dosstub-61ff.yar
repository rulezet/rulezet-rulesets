rule TTP_XOR_MULT_DOSStub_61ff {
  strings:
    $key_61ff = { 35 97 [2] 41 8f [2] 06 8d [2] 41 9c [2] 0f 90 [2] 03 9a [2] 14 91 [2] 0f df [2] 32 }

  condition:
    any of them
}
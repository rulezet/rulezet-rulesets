rule TTP_XOR_MULT_DOSStub_05ff {
  strings:
    $key_05ff = { 51 97 [2] 25 8f [2] 62 8d [2] 25 9c [2] 6b 90 [2] 67 9a [2] 70 91 [2] 6b df [2] 56 }

  condition:
    any of them
}
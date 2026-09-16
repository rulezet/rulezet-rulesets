rule TTP_XOR_MULT_DOSStub_2893 {
  strings:
    $key_2893 = { 7c fb [2] 08 e3 [2] 4f e1 [2] 08 f0 [2] 46 fc [2] 4a f6 [2] 5d fd [2] 46 b3 [2] 7b }

  condition:
    any of them
}
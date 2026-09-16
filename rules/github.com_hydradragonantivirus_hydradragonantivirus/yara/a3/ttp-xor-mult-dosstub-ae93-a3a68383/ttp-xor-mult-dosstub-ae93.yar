rule TTP_XOR_MULT_DOSStub_ae93 {
  strings:
    $key_ae93 = { fa fb [2] 8e e3 [2] c9 e1 [2] 8e f0 [2] c0 fc [2] cc f6 [2] db fd [2] c0 b3 [2] fd }

  condition:
    any of them
}
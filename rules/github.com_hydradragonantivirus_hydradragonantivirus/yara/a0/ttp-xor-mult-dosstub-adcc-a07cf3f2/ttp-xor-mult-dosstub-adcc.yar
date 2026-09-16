rule TTP_XOR_MULT_DOSStub_adcc {
  strings:
    $key_adcc = { f9 a4 [2] 8d bc [2] ca be [2] 8d af [2] c3 a3 [2] cf a9 [2] d8 a2 [2] c3 ec [2] fe }

  condition:
    any of them
}
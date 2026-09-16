rule TTP_XOR_MULT_DOSStub_e99c {
  strings:
    $key_e99c = { bd f4 [2] c9 ec [2] 8e ee [2] c9 ff [2] 87 f3 [2] 8b f9 [2] 9c f2 [2] 87 bc [2] ba }

  condition:
    any of them
}
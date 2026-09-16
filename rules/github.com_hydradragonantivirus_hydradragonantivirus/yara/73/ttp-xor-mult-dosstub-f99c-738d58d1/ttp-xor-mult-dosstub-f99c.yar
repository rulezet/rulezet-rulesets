rule TTP_XOR_MULT_DOSStub_f99c {
  strings:
    $key_f99c = { ad f4 [2] d9 ec [2] 9e ee [2] d9 ff [2] 97 f3 [2] 9b f9 [2] 8c f2 [2] 97 bc [2] aa }

  condition:
    any of them
}
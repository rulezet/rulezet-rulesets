rule TTP_XOR_MULT_DOSStub_a89c {
  strings:
    $key_a89c = { fc f4 [2] 88 ec [2] cf ee [2] 88 ff [2] c6 f3 [2] ca f9 [2] dd f2 [2] c6 bc [2] fb }

  condition:
    any of them
}
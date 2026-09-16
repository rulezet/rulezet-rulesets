rule TTP_XOR_MULT_DOSStub_afdc {
  strings:
    $key_afdc = { fb b4 [2] 8f ac [2] c8 ae [2] 8f bf [2] c1 b3 [2] cd b9 [2] da b2 [2] c1 fc [2] fc }

  condition:
    any of them
}
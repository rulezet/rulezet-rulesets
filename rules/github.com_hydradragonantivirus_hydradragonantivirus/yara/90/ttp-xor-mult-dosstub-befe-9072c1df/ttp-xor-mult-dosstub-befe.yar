rule TTP_XOR_MULT_DOSStub_befe {
  strings:
    $key_befe = { ea 96 [2] 9e 8e [2] d9 8c [2] 9e 9d [2] d0 91 [2] dc 9b [2] cb 90 [2] d0 de [2] ed }

  condition:
    any of them
}
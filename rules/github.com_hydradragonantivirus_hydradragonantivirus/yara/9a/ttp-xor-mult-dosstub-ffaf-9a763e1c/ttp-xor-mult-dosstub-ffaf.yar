rule TTP_XOR_MULT_DOSStub_ffaf {
  strings:
    $key_ffaf = { ab c7 [2] df df [2] 98 dd [2] df cc [2] 91 c0 [2] 9d ca [2] 8a c1 [2] 91 8f [2] ac }

  condition:
    any of them
}
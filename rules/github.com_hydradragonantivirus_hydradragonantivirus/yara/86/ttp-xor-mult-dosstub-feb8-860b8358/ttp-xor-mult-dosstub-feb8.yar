rule TTP_XOR_MULT_DOSStub_feb8 {
  strings:
    $key_feb8 = { aa d0 [2] de c8 [2] 99 ca [2] de db [2] 90 d7 [2] 9c dd [2] 8b d6 [2] 90 98 [2] ad }

  condition:
    any of them
}
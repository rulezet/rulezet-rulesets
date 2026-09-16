rule TTP_XOR_MULT_DOSStub_cbda {
  strings:
    $key_cbda = { 9f b2 [2] eb aa [2] ac a8 [2] eb b9 [2] a5 b5 [2] a9 bf [2] be b4 [2] a5 fa [2] 98 }

  condition:
    any of them
}
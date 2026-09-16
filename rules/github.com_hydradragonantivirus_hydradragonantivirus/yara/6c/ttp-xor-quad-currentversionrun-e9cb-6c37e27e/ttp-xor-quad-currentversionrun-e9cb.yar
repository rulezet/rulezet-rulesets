rule TTP_XOR_QUAD_CurrentVersionRun_e9cb {
  strings:
    $key_e9cb = { ba a4 [2] 9e aa [2] b5 86 [2] 9b a4 [2] 8f bf [2] 80 a5 [2] 9e b8 [2] 9c b9 [2] 87 bf [2] 9b b8 [2] 87 97 }

  condition:
    any of them
}
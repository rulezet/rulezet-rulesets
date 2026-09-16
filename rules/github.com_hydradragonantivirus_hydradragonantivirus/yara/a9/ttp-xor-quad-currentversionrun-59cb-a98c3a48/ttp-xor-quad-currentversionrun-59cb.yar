rule TTP_XOR_QUAD_CurrentVersionRun_59cb {
  strings:
    $key_59cb = { 0a a4 [2] 2e aa [2] 05 86 [2] 2b a4 [2] 3f bf [2] 30 a5 [2] 2e b8 [2] 2c b9 [2] 37 bf [2] 2b b8 [2] 37 97 }

  condition:
    any of them
}
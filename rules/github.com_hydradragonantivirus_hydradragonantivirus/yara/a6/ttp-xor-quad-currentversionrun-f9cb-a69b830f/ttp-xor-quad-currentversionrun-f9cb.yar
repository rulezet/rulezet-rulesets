rule TTP_XOR_QUAD_CurrentVersionRun_f9cb {
  strings:
    $key_f9cb = { aa a4 [2] 8e aa [2] a5 86 [2] 8b a4 [2] 9f bf [2] 90 a5 [2] 8e b8 [2] 8c b9 [2] 97 bf [2] 8b b8 [2] 97 97 }

  condition:
    any of them
}
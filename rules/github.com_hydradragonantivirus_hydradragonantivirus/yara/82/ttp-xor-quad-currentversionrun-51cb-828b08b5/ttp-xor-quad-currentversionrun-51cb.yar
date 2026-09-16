rule TTP_XOR_QUAD_CurrentVersionRun_51cb {
  strings:
    $key_51cb = { 02 a4 [2] 26 aa [2] 0d 86 [2] 23 a4 [2] 37 bf [2] 38 a5 [2] 26 b8 [2] 24 b9 [2] 3f bf [2] 23 b8 [2] 3f 97 }

  condition:
    any of them
}
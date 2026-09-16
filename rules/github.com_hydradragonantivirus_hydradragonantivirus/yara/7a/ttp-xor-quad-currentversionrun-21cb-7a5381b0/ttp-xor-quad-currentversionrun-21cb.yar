rule TTP_XOR_QUAD_CurrentVersionRun_21cb {
  strings:
    $key_21cb = { 72 a4 [2] 56 aa [2] 7d 86 [2] 53 a4 [2] 47 bf [2] 48 a5 [2] 56 b8 [2] 54 b9 [2] 4f bf [2] 53 b8 [2] 4f 97 }

  condition:
    any of them
}
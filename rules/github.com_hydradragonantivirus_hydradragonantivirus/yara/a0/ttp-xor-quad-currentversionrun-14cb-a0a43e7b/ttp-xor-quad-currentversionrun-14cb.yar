rule TTP_XOR_QUAD_CurrentVersionRun_14cb {
  strings:
    $key_14cb = { 47 a4 [2] 63 aa [2] 48 86 [2] 66 a4 [2] 72 bf [2] 7d a5 [2] 63 b8 [2] 61 b9 [2] 7a bf [2] 66 b8 [2] 7a 97 }

  condition:
    any of them
}
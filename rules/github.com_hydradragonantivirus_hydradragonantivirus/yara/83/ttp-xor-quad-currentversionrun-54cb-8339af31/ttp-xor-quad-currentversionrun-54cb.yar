rule TTP_XOR_QUAD_CurrentVersionRun_54cb {
  strings:
    $key_54cb = { 07 a4 [2] 23 aa [2] 08 86 [2] 26 a4 [2] 32 bf [2] 3d a5 [2] 23 b8 [2] 21 b9 [2] 3a bf [2] 26 b8 [2] 3a 97 }

  condition:
    any of them
}
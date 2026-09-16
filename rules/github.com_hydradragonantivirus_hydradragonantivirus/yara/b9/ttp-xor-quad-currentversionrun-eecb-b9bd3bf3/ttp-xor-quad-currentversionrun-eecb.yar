rule TTP_XOR_QUAD_CurrentVersionRun_eecb {
  strings:
    $key_eecb = { bd a4 [2] 99 aa [2] b2 86 [2] 9c a4 [2] 88 bf [2] 87 a5 [2] 99 b8 [2] 9b b9 [2] 80 bf [2] 9c b8 [2] 80 97 }

  condition:
    any of them
}
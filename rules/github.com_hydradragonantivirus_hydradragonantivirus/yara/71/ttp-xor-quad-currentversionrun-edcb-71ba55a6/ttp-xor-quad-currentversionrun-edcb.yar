rule TTP_XOR_QUAD_CurrentVersionRun_edcb {
  strings:
    $key_edcb = { be a4 [2] 9a aa [2] b1 86 [2] 9f a4 [2] 8b bf [2] 84 a5 [2] 9a b8 [2] 98 b9 [2] 83 bf [2] 9f b8 [2] 83 97 }

  condition:
    any of them
}
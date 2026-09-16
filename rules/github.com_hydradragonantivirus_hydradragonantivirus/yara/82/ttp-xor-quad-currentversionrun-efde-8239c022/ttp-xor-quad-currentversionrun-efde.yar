rule TTP_XOR_QUAD_CurrentVersionRun_efde {
  strings:
    $key_efde = { bc b1 [2] 98 bf [2] b3 93 [2] 9d b1 [2] 89 aa [2] 86 b0 [2] 98 ad [2] 9a ac [2] 81 aa [2] 9d ad [2] 81 82 }

  condition:
    any of them
}
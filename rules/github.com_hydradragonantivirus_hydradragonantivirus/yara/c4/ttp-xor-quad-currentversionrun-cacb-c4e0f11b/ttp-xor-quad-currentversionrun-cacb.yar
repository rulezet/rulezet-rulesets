rule TTP_XOR_QUAD_CurrentVersionRun_cacb {
  strings:
    $key_cacb = { 99 a4 [2] bd aa [2] 96 86 [2] b8 a4 [2] ac bf [2] a3 a5 [2] bd b8 [2] bf b9 [2] a4 bf [2] b8 b8 [2] a4 97 }

  condition:
    any of them
}
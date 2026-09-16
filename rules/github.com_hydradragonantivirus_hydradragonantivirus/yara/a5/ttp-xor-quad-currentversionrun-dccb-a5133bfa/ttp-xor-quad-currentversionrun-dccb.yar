rule TTP_XOR_QUAD_CurrentVersionRun_dccb {
  strings:
    $key_dccb = { 8f a4 [2] ab aa [2] 80 86 [2] ae a4 [2] ba bf [2] b5 a5 [2] ab b8 [2] a9 b9 [2] b2 bf [2] ae b8 [2] b2 97 }

  condition:
    any of them
}
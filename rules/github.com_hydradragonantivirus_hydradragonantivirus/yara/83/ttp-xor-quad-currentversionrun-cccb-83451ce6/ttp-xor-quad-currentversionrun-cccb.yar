rule TTP_XOR_QUAD_CurrentVersionRun_cccb {
  strings:
    $key_cccb = { 9f a4 [2] bb aa [2] 90 86 [2] be a4 [2] aa bf [2] a5 a5 [2] bb b8 [2] b9 b9 [2] a2 bf [2] be b8 [2] a2 97 }

  condition:
    any of them
}
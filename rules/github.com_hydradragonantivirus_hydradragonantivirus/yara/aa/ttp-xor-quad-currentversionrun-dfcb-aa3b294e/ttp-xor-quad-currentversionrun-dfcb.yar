rule TTP_XOR_QUAD_CurrentVersionRun_dfcb {
  strings:
    $key_dfcb = { 8c a4 [2] a8 aa [2] 83 86 [2] ad a4 [2] b9 bf [2] b6 a5 [2] a8 b8 [2] aa b9 [2] b1 bf [2] ad b8 [2] b1 97 }

  condition:
    any of them
}
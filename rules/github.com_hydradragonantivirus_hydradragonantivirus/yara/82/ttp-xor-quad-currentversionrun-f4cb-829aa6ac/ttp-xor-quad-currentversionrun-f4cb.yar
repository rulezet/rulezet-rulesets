rule TTP_XOR_QUAD_CurrentVersionRun_f4cb {
  strings:
    $key_f4cb = { a7 a4 [2] 83 aa [2] a8 86 [2] 86 a4 [2] 92 bf [2] 9d a5 [2] 83 b8 [2] 81 b9 [2] 9a bf [2] 86 b8 [2] 9a 97 }

  condition:
    any of them
}
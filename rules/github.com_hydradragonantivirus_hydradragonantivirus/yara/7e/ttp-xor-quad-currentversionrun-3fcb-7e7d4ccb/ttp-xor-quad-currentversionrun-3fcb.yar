rule TTP_XOR_QUAD_CurrentVersionRun_3fcb {
  strings:
    $key_3fcb = { 6c a4 [2] 48 aa [2] 63 86 [2] 4d a4 [2] 59 bf [2] 56 a5 [2] 48 b8 [2] 4a b9 [2] 51 bf [2] 4d b8 [2] 51 97 }

  condition:
    any of them
}
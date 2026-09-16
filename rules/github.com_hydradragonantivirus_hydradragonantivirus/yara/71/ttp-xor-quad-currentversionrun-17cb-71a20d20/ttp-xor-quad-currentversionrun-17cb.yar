rule TTP_XOR_QUAD_CurrentVersionRun_17cb {
  strings:
    $key_17cb = { 44 a4 [2] 60 aa [2] 4b 86 [2] 65 a4 [2] 71 bf [2] 7e a5 [2] 60 b8 [2] 62 b9 [2] 79 bf [2] 65 b8 [2] 79 97 }

  condition:
    any of them
}
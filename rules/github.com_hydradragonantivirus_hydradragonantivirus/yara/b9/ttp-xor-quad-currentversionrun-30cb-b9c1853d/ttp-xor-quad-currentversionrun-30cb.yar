rule TTP_XOR_QUAD_CurrentVersionRun_30cb {
  strings:
    $key_30cb = { 63 a4 [2] 47 aa [2] 6c 86 [2] 42 a4 [2] 56 bf [2] 59 a5 [2] 47 b8 [2] 45 b9 [2] 5e bf [2] 42 b8 [2] 5e 97 }

  condition:
    any of them
}
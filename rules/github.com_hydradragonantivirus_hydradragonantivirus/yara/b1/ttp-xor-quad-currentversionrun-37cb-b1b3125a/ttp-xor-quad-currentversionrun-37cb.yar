rule TTP_XOR_QUAD_CurrentVersionRun_37cb {
  strings:
    $key_37cb = { 64 a4 [2] 40 aa [2] 6b 86 [2] 45 a4 [2] 51 bf [2] 5e a5 [2] 40 b8 [2] 42 b9 [2] 59 bf [2] 45 b8 [2] 59 97 }

  condition:
    any of them
}
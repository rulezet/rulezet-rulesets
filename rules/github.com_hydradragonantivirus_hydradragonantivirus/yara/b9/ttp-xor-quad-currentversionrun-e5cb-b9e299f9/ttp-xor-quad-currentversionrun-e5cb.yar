rule TTP_XOR_QUAD_CurrentVersionRun_e5cb {
  strings:
    $key_e5cb = { b6 a4 [2] 92 aa [2] b9 86 [2] 97 a4 [2] 83 bf [2] 8c a5 [2] 92 b8 [2] 90 b9 [2] 8b bf [2] 97 b8 [2] 8b 97 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_1726 {
  strings:
    $key_1726 = { 44 49 [2] 60 47 [2] 4b 6b [2] 65 49 [2] 71 52 [2] 7e 48 [2] 60 55 [2] 62 54 [2] 79 52 [2] 65 55 [2] 79 7a }

  condition:
    any of them
}
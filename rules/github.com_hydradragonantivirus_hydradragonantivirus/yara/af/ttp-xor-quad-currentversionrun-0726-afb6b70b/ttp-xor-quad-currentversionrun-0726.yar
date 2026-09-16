rule TTP_XOR_QUAD_CurrentVersionRun_0726 {
  strings:
    $key_0726 = { 54 49 [2] 70 47 [2] 5b 6b [2] 75 49 [2] 61 52 [2] 6e 48 [2] 70 55 [2] 72 54 [2] 69 52 [2] 75 55 [2] 69 7a }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_2227 {
  strings:
    $key_2227 = { 71 48 [2] 55 46 [2] 7e 6a [2] 50 48 [2] 44 53 [2] 4b 49 [2] 55 54 [2] 57 55 [2] 4c 53 [2] 50 54 [2] 4c 7b }

  condition:
    any of them
}
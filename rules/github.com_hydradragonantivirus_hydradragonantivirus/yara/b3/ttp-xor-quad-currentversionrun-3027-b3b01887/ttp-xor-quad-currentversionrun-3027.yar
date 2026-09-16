rule TTP_XOR_QUAD_CurrentVersionRun_3027 {
  strings:
    $key_3027 = { 63 48 [2] 47 46 [2] 6c 6a [2] 42 48 [2] 56 53 [2] 59 49 [2] 47 54 [2] 45 55 [2] 5e 53 [2] 42 54 [2] 5e 7b }

  condition:
    any of them
}
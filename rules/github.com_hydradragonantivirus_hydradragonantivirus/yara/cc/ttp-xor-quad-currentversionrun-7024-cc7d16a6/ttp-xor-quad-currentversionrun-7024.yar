rule TTP_XOR_QUAD_CurrentVersionRun_7024 {
  strings:
    $key_7024 = { 23 4b [2] 07 45 [2] 2c 69 [2] 02 4b [2] 16 50 [2] 19 4a [2] 07 57 [2] 05 56 [2] 1e 50 [2] 02 57 [2] 1e 78 }

  condition:
    any of them
}
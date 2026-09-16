rule TTP_XOR_QUAD_CurrentVersionRun_f027 {
  strings:
    $key_f027 = { a3 48 [2] 87 46 [2] ac 6a [2] 82 48 [2] 96 53 [2] 99 49 [2] 87 54 [2] 85 55 [2] 9e 53 [2] 82 54 [2] 9e 7b }

  condition:
    any of them
}
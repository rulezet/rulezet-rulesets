rule TTP_XOR_QUAD_CurrentVersionRun_39f7 {
  strings:
    $key_39f7 = { 6a 98 [2] 4e 96 [2] 65 ba [2] 4b 98 [2] 5f 83 [2] 50 99 [2] 4e 84 [2] 4c 85 [2] 57 83 [2] 4b 84 [2] 57 ab }

  condition:
    any of them
}
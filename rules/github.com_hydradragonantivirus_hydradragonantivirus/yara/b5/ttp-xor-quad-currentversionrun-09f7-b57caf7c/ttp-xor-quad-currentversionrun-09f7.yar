rule TTP_XOR_QUAD_CurrentVersionRun_09f7 {
  strings:
    $key_09f7 = { 5a 98 [2] 7e 96 [2] 55 ba [2] 7b 98 [2] 6f 83 [2] 60 99 [2] 7e 84 [2] 7c 85 [2] 67 83 [2] 7b 84 [2] 67 ab }

  condition:
    any of them
}
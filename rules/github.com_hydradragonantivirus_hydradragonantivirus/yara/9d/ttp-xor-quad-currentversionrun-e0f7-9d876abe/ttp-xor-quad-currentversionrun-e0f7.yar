rule TTP_XOR_QUAD_CurrentVersionRun_e0f7 {
  strings:
    $key_e0f7 = { b3 98 [2] 97 96 [2] bc ba [2] 92 98 [2] 86 83 [2] 89 99 [2] 97 84 [2] 95 85 [2] 8e 83 [2] 92 84 [2] 8e ab }

  condition:
    any of them
}